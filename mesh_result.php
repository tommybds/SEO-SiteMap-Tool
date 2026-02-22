<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('mesh_result_get', $ip, 180, 60);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit resultat maillage atteint.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$meshId = sanitize_job_id((string) ($_GET['mesh_id'] ?? ''));
if ($meshId === null) {
    respond_json(['error' => 'mesh_id invalide'], 400);
}

$stored = read_mesh_result($meshId);
if (!is_array($stored)) {
    respond_json(['error' => 'Resultat maillage introuvable'], 404);
}

$mesh = $stored['mesh'] ?? null;
if (!is_array($mesh)) {
    respond_json(['error' => 'Resultat maillage invalide'], 500);
}

respond_json([
    'ok' => true,
    'mesh_id' => $meshId,
    'created_at' => $stored['created_at'] ?? null,
    'mesh' => $mesh,
]);
