<?php
declare(strict_types=1);

require __DIR__ . '/auth.php';
ensure_storage_dirs();
auth_session_start();

if (current_user() !== null) {
    header('Location: history.php');
    exit;
}

$error = '';
$emailValue = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = client_ip();
    $rl = enforce_rate_limit('auth_login', $ip, 8, 900);
    if (!$rl['allowed']) {
        $error = 'Trop de tentatives, reessaye dans ' . (int) $rl['retry_after'] . 's.';
    } elseif (!csrf_check((string) ($_POST['_csrf'] ?? ''))) {
        $error = 'Jeton CSRF invalide, recharge la page.';
    } elseif (!honeypot_ok($_POST)) {
        usleep(random_int(400000, 1200000));
        $error = 'Identifiants invalides.';
    } else {
        $emailValue = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        $err = '';
        $user = user_login($emailValue, $password, $err);
        if ($user === null) {
            $error = $err !== '' ? $err : 'Identifiants invalides.';
        } else {
            $next = (string) ($_POST['next'] ?? 'history.php');
            if (!preg_match('/^[a-z0-9_\-\.\/]+$/i', $next) || str_contains($next, '..') || str_starts_with($next, '/') || str_starts_with($next, 'http')) {
                $next = 'history.php';
            }
            header('Location: ' . $next);
            exit;
        }
    }
}

$nextValue = htmlspecialchars((string) ($_GET['next'] ?? 'history.php'), ENT_QUOTES, 'UTF-8');

$errorBlock = $error !== ''
    ? '<div class="auth-alert auth-alert-error">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</div>'
    : '';

$body = '<h1>Connexion</h1>'
    . $errorBlock
    . '<form method="post" class="auth-form" autocomplete="off" novalidate>'
    . csrf_field()
    . honeypot_field()
    . '<input type="hidden" name="next" value="' . $nextValue . '">'
    . '<label>Email<input type="email" name="email" required autocomplete="username" value="' . htmlspecialchars($emailValue, ENT_QUOTES, 'UTF-8') . '"></label>'
    . '<label>Mot de passe<input type="password" name="password" required autocomplete="current-password"></label>'
    . '<button type="submit" class="auth-submit">Se connecter</button>'
    . '</form>'
    . '<p class="auth-alt">Pas de compte ? <a href="register.php">Creer un compte</a></p>';

echo html_layout('Connexion', $body, null);
