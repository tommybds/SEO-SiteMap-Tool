<?php
declare(strict_types=1);

require __DIR__ . '/auth.php';
auth_session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && csrf_check((string) ($_POST['_csrf'] ?? ''))) {
    user_logout();
}

header('Location: index.html');
exit;
