<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('mesh_run', $ip, 12, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit maillage atteint. Reessaye plus tard.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$input = array_merge($_POST, get_json_input());
$startUrl = trim((string) ($input['start_url'] ?? ''));
if ($startUrl === '') {
    respond_json(['error' => 'Le champ start_url est obligatoire.'], 400);
}

$validationError = '';
if (!validate_public_url($startUrl, $validationError)) {
    respond_json(['error' => $validationError], 400);
}

$maxPages = clamp_int($input['max_pages'] ?? 80, 10, 300, 80);
$timeout = clamp_int($input['timeout'] ?? 12, 3, 30, 12);
$maxEdges = clamp_int($input['max_edges'] ?? 800, 100, 2000, 800);

$scriptPath = internal_mesh_script_path();
if (!is_file($scriptPath)) {
    respond_json(['error' => 'Script maillage introuvable sur le serveur.'], 500);
}

if (!function_exists('shell_exec')) {
    respond_json(['error' => 'shell_exec est desactive sur cet hebergement.'], 500);
}

$command = 'python3 ' . escapeshellarg($scriptPath)
    . ' --start-url ' . escapeshellarg($startUrl)
    . ' --max-pages ' . escapeshellarg((string) $maxPages)
    . ' --timeout ' . escapeshellarg((string) $timeout)
    . ' --max-edges ' . escapeshellarg((string) $maxEdges)
    . ' 2>&1';

$raw = shell_exec($command);
if (!is_string($raw) || trim($raw) === '') {
    respond_json(['error' => 'Reponse vide du script maillage.'], 500);
}

$decoded = json_decode($raw, true);
if (!is_array($decoded)) {
    respond_json([
        'error' => 'Reponse invalide du script maillage.',
        'raw' => trim(substr($raw, 0, 500)),
    ], 500);
}

if (empty($decoded['ok'])) {
    $error = trim((string) ($decoded['error'] ?? 'Erreur maillage inconnue.'));
    respond_json(['error' => $error], 400);
}

$payload = $decoded;
try {
    $meshId = bin2hex(random_bytes(10));
    $stored = [
        'mesh_id' => $meshId,
        'created_at' => gmdate('c'),
        'start_url' => $startUrl,
        'params' => [
            'max_pages' => $maxPages,
            'timeout' => $timeout,
            'max_edges' => $maxEdges,
        ],
        'mesh' => is_array($decoded['mesh'] ?? null) ? $decoded['mesh'] : [],
    ];

    if (write_mesh_result($meshId, $stored)) {
        $payload['mesh_id'] = $meshId;
    }
} catch (Throwable $e) {
    // Keep API success even if storing share data failed.
}

respond_json($payload);
