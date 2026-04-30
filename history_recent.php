<?php
declare(strict_types=1);

require __DIR__ . '/auth.php';
auth_session_start();

$user = current_user();
if ($user === null) {
    respond_json(['authenticated' => false, 'entries' => []]);
}

$validTypes = [
    'sitemap_audit',
    'mesh_audit',
    'tech_audit',
    'security_audit',
    'accessibility_audit',
    'images_audit',
    'geo_audit',
];

$type = (string) ($_GET['type'] ?? '');
if ($type !== '' && !in_array($type, $validTypes, true)) {
    $type = '';
}

$limit = clamp_int($_GET['limit'] ?? 8, 1, 50, 8);

$entries = scan_history_read((string) $user['id'], 500);

if ($type !== '') {
    $entries = array_values(array_filter($entries, static function ($e) use ($type) {
        return (string) ($e['type'] ?? '') === $type;
    }));
}

$entries = array_slice($entries, 0, $limit);

$out = [];
foreach ($entries as $e) {
    $out[] = [
        'ts' => $e['ts'] ?? null,
        'type' => $e['type'] ?? null,
        'target' => $e['target'] ?? null,
        'job_id' => $e['job_id'] ?? null,
        'job_kind' => $e['job_kind'] ?? null,
    ];
}

respond_json([
    'authenticated' => true,
    'entries' => $out,
]);
