<?php
declare(strict_types=1);

require __DIR__ . '/auth.php';
auth_session_start();

$user = current_user();
if ($user === null) {
    respond_json(['authenticated' => false, 'csrf' => csrf_token()]);
}

respond_json([
    'authenticated' => true,
    'user' => user_public_view($user),
    'csrf' => csrf_token(),
]);
