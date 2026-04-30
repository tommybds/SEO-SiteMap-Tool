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
$success = '';
$emailValue = '';
$store = users_read();
$isFirstAccount = users_total($store) === 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = client_ip();
    $rl = enforce_rate_limit('auth_register', $ip, 5, 900);
    if (!$rl['allowed']) {
        $error = 'Trop de tentatives, reessaye dans ' . (int) $rl['retry_after'] . 's.';
    } elseif (!csrf_check((string) ($_POST['_csrf'] ?? ''))) {
        $error = 'Jeton CSRF invalide, recharge la page.';
    } elseif (!honeypot_ok($_POST)) {
        usleep(random_int(400000, 1200000));
        $error = 'Soumission invalide.';
    } else {
        $emailValue = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $confirm = (string) ($_POST['password_confirm'] ?? '');

        if ($password !== $confirm) {
            $error = 'Les mots de passe ne correspondent pas.';
        } else {
            $err = '';
            $created = user_create($emailValue, $password, $err);
            if ($created === null) {
                $error = $err !== '' ? $err : 'Inscription impossible.';
            } else {
                if (($created['status'] ?? '') === 'active') {
                    $success = 'Compte administrateur cree. Tu peux te connecter.';
                } else {
                    $success = 'Compte cree. Un administrateur doit l approuver avant la connexion.';
                }
                $emailValue = '';
            }
        }
    }
}

$errorBlock = $error !== ''
    ? '<div class="auth-alert auth-alert-error">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</div>'
    : '';
$successBlock = $success !== ''
    ? '<div class="auth-alert auth-alert-success">' . htmlspecialchars($success, ENT_QUOTES, 'UTF-8') . '</div>'
    : '';

$intro = $isFirstAccount
    ? '<p class="auth-intro">Aucun compte n existe encore. Le premier compte cree devient automatiquement <strong>administrateur</strong>.</p>'
    : '<p class="auth-intro">Les nouveaux comptes doivent etre approuves par un administrateur avant de pouvoir se connecter.</p>';

$body = '<h1>Creer un compte</h1>'
    . $intro
    . $errorBlock
    . $successBlock
    . '<form method="post" class="auth-form" autocomplete="off" novalidate>'
    . csrf_field()
    . honeypot_field()
    . '<label>Email<input type="email" name="email" required autocomplete="username" value="' . htmlspecialchars($emailValue, ENT_QUOTES, 'UTF-8') . '"></label>'
    . '<label>Mot de passe (min ' . AUTH_PASSWORD_MIN . ' caracteres)<input type="password" name="password" required minlength="' . AUTH_PASSWORD_MIN . '" autocomplete="new-password"></label>'
    . '<label>Confirmer le mot de passe<input type="password" name="password_confirm" required minlength="' . AUTH_PASSWORD_MIN . '" autocomplete="new-password"></label>'
    . '<button type="submit" class="auth-submit">S inscrire</button>'
    . '</form>'
    . '<p class="auth-alt">Deja un compte ? <a href="login.php">Se connecter</a></p>';

echo html_layout('Creer un compte', $body, null);
