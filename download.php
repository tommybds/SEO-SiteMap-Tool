<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo 'Method not allowed';
    exit;
}

$ip = client_ip();
$limit = enforce_rate_limit('download_csv', $ip, 60, 60);
if (!$limit['allowed']) {
    http_response_code(429);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Rate limit atteint.';
    exit;
}

$jobId = sanitize_job_id((string) ($_GET['job_id'] ?? ''));
if ($jobId === null) {
    http_response_code(400);
    echo 'job_id invalide';
    exit;
}

$path = report_path($jobId);
if (!is_file($path)) {
    http_response_code(404);
    echo 'Rapport introuvable';
    exit;
}

header('Content-Type: text/csv; charset=utf-8');
header('Content-Length: ' . (string) filesize($path));
header('Content-Disposition: attachment; filename="seo_report_' . $jobId . '.csv"');
readfile($path);
