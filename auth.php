<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

const USERS_FILE = STORAGE_DIR . '/users.json';
const AUTH_SCAN_HISTORY_FILE = STORAGE_DIR . '/scan_history.json';
const AUTH_PASSWORD_MIN = 12;

function auth_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $secure = (
        (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
        || (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'
        || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443
    );

    session_name('seo_sess');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');
    session_start();

    if (empty($_SESSION['_csrf'])) {
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    }
}

function csrf_token(): string
{
    auth_session_start();
    return (string) $_SESSION['_csrf'];
}

function csrf_check(?string $token): bool
{
    auth_session_start();
    $expected = (string) ($_SESSION['_csrf'] ?? '');
    if ($expected === '' || !is_string($token) || $token === '') {
        return false;
    }
    return hash_equals($expected, $token);
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

function honeypot_field(): string
{
    return '<div aria-hidden="true" style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;">'
        . '<label>Site web (laisser vide)</label>'
        . '<input type="text" name="website" tabindex="-1" autocomplete="off" value="">'
        . '<input type="text" name="hp_started_at" value="' . (string) time() . '">'
        . '</div>';
}

function honeypot_ok(array $input): bool
{
    if (trim((string) ($input['website'] ?? '')) !== '') {
        return false;
    }
    $started = (int) ($input['hp_started_at'] ?? 0);
    if ($started <= 0) {
        return false;
    }
    if (time() - $started < 2) {
        return false;
    }
    return true;
}

function users_read(): array
{
    if (!is_file(USERS_FILE)) {
        return ['users' => []];
    }
    $raw = @file_get_contents(USERS_FILE);
    if (!is_string($raw) || trim($raw) === '') {
        return ['users' => []];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !isset($decoded['users']) || !is_array($decoded['users'])) {
        return ['users' => []];
    }
    return $decoded;
}

function users_write(array $store): bool
{
    ensure_storage_dirs();
    $payload = json_encode($store, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($payload === false) {
        return false;
    }
    return file_put_contents(USERS_FILE, $payload, LOCK_EX) !== false;
}

function users_count_active_admins(array $store): int
{
    $count = 0;
    foreach ($store['users'] as $user) {
        if (($user['role'] ?? '') === 'admin' && ($user['status'] ?? '') === 'active') {
            $count++;
        }
    }
    return $count;
}

function users_total(array $store): int
{
    return count($store['users']);
}

function users_find_by_email(array $store, string $email): ?array
{
    $email = strtolower(trim($email));
    foreach ($store['users'] as $user) {
        if (strtolower((string) ($user['email'] ?? '')) === $email) {
            return $user;
        }
    }
    return null;
}

function users_find_by_id(array $store, string $id): ?array
{
    foreach ($store['users'] as $user) {
        if ((string) ($user['id'] ?? '') === $id) {
            return $user;
        }
    }
    return null;
}

function user_create(string $email, string $password, string &$error): ?array
{
    $error = '';
    $email = strtolower(trim($email));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Email invalide.';
        return null;
    }
    if (strlen($password) < AUTH_PASSWORD_MIN) {
        $error = 'Mot de passe trop court (min ' . AUTH_PASSWORD_MIN . ' caracteres).';
        return null;
    }

    $store = users_read();
    if (users_find_by_email($store, $email) !== null) {
        $error = 'Cet email est deja enregistre.';
        return null;
    }

    $isFirst = users_total($store) === 0;
    $id = bin2hex(random_bytes(8));
    $now = gmdate('c');

    $user = [
        'id' => $id,
        'email' => $email,
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'role' => $isFirst ? 'admin' : 'user',
        'status' => $isFirst ? 'active' : 'pending',
        'created_at' => $now,
        'approved_at' => $isFirst ? $now : null,
        'approved_by' => $isFirst ? $id : null,
        'last_login_at' => null,
    ];

    $store['users'][] = $user;
    if (!users_write($store)) {
        $error = 'Impossible d ecrire les comptes.';
        return null;
    }

    return $user;
}

function user_update(string $id, callable $mutator): ?array
{
    $store = users_read();
    $found = null;
    foreach ($store['users'] as $idx => $user) {
        if ((string) ($user['id'] ?? '') === $id) {
            $next = $mutator($user);
            if (!is_array($next)) {
                return null;
            }
            $store['users'][$idx] = $next;
            $found = $next;
            break;
        }
    }
    if ($found === null) {
        return null;
    }
    if (!users_write($store)) {
        return null;
    }
    return $found;
}

function user_delete(string $id): bool
{
    $store = users_read();
    $kept = [];
    $removed = false;
    foreach ($store['users'] as $user) {
        if ((string) ($user['id'] ?? '') === $id) {
            $removed = true;
            continue;
        }
        $kept[] = $user;
    }
    if (!$removed) {
        return false;
    }
    $store['users'] = $kept;
    return users_write($store);
}

function user_login(string $email, string $password, string &$error): ?array
{
    $error = '';
    $store = users_read();
    $user = users_find_by_email($store, $email);

    $genericError = 'Identifiants invalides.';

    if ($user === null) {
        password_verify($password, '$2y$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalid');
        $error = $genericError;
        return null;
    }

    $hash = (string) ($user['password_hash'] ?? '');
    if (!password_verify($password, $hash)) {
        $error = $genericError;
        return null;
    }

    $status = (string) ($user['status'] ?? '');
    if ($status === 'pending') {
        $error = 'Compte en attente d approbation par l administrateur.';
        return null;
    }
    if ($status !== 'active') {
        $error = 'Compte desactive.';
        return null;
    }

    auth_session_start();
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    $_SESSION['login_at'] = time();

    user_update((string) $user['id'], static function (array $u): array {
        $u['last_login_at'] = gmdate('c');
        return $u;
    });

    return $user;
}

function user_logout(): void
{
    auth_session_start();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'] ?? '',
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax',
        ]);
    }
    session_destroy();
}

function current_user(): ?array
{
    auth_session_start();
    $id = (string) ($_SESSION['user_id'] ?? '');
    if ($id === '') {
        return null;
    }
    $store = users_read();
    $user = users_find_by_id($store, $id);
    if ($user === null) {
        $_SESSION = [];
        return null;
    }
    if (($user['status'] ?? '') !== 'active') {
        $_SESSION = [];
        return null;
    }
    return $user;
}

function require_user(): array
{
    $user = current_user();
    if ($user === null) {
        header('Location: login.php');
        exit;
    }
    return $user;
}

function require_admin(): array
{
    $user = require_user();
    if (($user['role'] ?? '') !== 'admin') {
        http_response_code(403);
        echo '<!doctype html><meta charset="utf-8"><title>403</title><p>Acces refuse.</p>';
        exit;
    }
    return $user;
}

function require_user_json(): array
{
    $user = current_user();
    if ($user === null) {
        respond_json(['error' => 'Authentification requise.'], 401);
    }
    return $user;
}

function require_admin_json(): array
{
    $user = require_user_json();
    if (($user['role'] ?? '') !== 'admin') {
        respond_json(['error' => 'Acces administrateur requis.'], 403);
    }
    return $user;
}

function user_public_view(array $user): array
{
    return [
        'id' => (string) ($user['id'] ?? ''),
        'email' => (string) ($user['email'] ?? ''),
        'role' => (string) ($user['role'] ?? 'user'),
        'status' => (string) ($user['status'] ?? 'pending'),
        'created_at' => $user['created_at'] ?? null,
        'last_login_at' => $user['last_login_at'] ?? null,
    ];
}

function scan_history_append(array $entry): bool
{
    ensure_storage_dirs();
    $entry['ts'] = $entry['ts'] ?? gmdate('c');

    $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($line === false) {
        return false;
    }

    $fp = @fopen(AUTH_SCAN_HISTORY_FILE, 'ab');
    if ($fp === false) {
        return false;
    }
    $ok = false;
    if (flock($fp, LOCK_EX)) {
        $ok = fwrite($fp, $line . "\n") !== false;
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $ok;
}

function scan_history_log(string $type, string $target, array $extra = []): void
{
    $user = current_user();
    $entry = array_merge([
        'type' => $type,
        'target' => $target,
        'user_id' => $user['id'] ?? null,
        'user_email' => $user['email'] ?? null,
        'ip' => client_ip(),
    ], $extra);
    scan_history_append($entry);
}

function scan_history_read(?string $userIdFilter, int $limit = 200): array
{
    if (!is_file(AUTH_SCAN_HISTORY_FILE)) {
        return [];
    }
    $fp = @fopen(AUTH_SCAN_HISTORY_FILE, 'rb');
    if ($fp === false) {
        return [];
    }

    $buffer = '';
    $size = filesize(AUTH_SCAN_HISTORY_FILE) ?: 0;
    if ($size > 5_000_000) {
        fseek($fp, -5_000_000, SEEK_END);
        fgets($fp);
    }
    while (!feof($fp)) {
        $buffer .= fread($fp, 65536);
    }
    fclose($fp);

    $lines = preg_split('/\r?\n/', $buffer) ?: [];
    $entries = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $decoded = json_decode($line, true);
        if (!is_array($decoded)) {
            continue;
        }
        if ($userIdFilter !== null) {
            if ((string) ($decoded['user_id'] ?? '') !== $userIdFilter) {
                continue;
            }
        }
        $entries[] = $decoded;
    }

    usort($entries, static function (array $a, array $b): int {
        return strcmp((string) ($b['ts'] ?? ''), (string) ($a['ts'] ?? ''));
    });

    return array_slice($entries, 0, max(1, $limit));
}

function html_layout(string $title, string $body, ?array $user = null): string
{
    $userBar = '';
    if ($user !== null) {
        $email = htmlspecialchars((string) $user['email'], ENT_QUOTES, 'UTF-8');
        $isAdmin = ($user['role'] ?? '') === 'admin';
        $adminLink = $isAdmin ? '<a href="admin_users.php">Administration</a>' : '';
        $userBar = '<nav class="auth-bar"><span class="auth-bar-user">' . $email
            . ($isAdmin ? ' <span class="auth-bar-pill">admin</span>' : '')
            . '</span><a href="index.html">Accueil</a><a href="history.php">Historique</a>'
            . $adminLink
            . '<form method="post" action="logout.php" class="auth-bar-logout">'
            . csrf_field()
            . '<button type="submit" class="auth-bar-link">Se deconnecter</button>'
            . '</form></nav>';
    } else {
        $userBar = '<nav class="auth-bar"><a href="index.html">Accueil</a><a href="login.php">Se connecter</a><a href="register.php">Creer un compte</a></nav>';
    }

    return '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex,nofollow">'
        . '<title>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</title>'
        . '<link rel="icon" href="favicon.svg" type="image/svg+xml">'
        . '<link rel="preconnect" href="https://rsms.me/">'
        . '<link rel="stylesheet" href="https://rsms.me/inter/inter.css">'
        . '<link rel="stylesheet" href="styles.css?v=20260430-3">'
        . '<link rel="stylesheet" href="css/auth.css?v=20260430-4">'
        . '</head><body><div class="wrap">'
        . $userBar
        . '<div class="card">'
        . $body
        . '</div></div></body></html>';
}
