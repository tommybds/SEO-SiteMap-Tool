<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('preview_csv', $ip, 120, 60);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit preview atteint.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$jobId = sanitize_job_id((string) ($_GET['job_id'] ?? ''));
if ($jobId === null) {
    respond_json(['error' => 'job_id invalide'], 400);
}

$rows = clamp_int($_GET['rows'] ?? 120, 10, 500, 120);
$path = report_path($jobId);
if (!is_file($path)) {
    respond_json(['error' => 'Rapport introuvable'], 404);
}

$preview = read_csv_preview($path, $rows);
respond_json([
    'job_id' => $jobId,
    'preview' => $preview,
]);
