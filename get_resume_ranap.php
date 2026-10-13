<?php
header('Content-Type: application/json; charset=utf-8');
require_once 'auth.php';

$no_rawat = isset($_GET['no_rawat']) ? trim($_GET['no_rawat']) : '';

if (empty($no_rawat)) {
    echo json_encode(['status' => 'error', 'message' => 'No. Rawat tidak valid.']);
    exit();
}

$query = "SELECT resume_pasien_ranap.*, dokter.nm_dokter 
          FROM resume_pasien_ranap 
          LEFT JOIN dokter ON resume_pasien_ranap.kd_dokter = dokter.kd_dokter 
          WHERE resume_pasien_ranap.no_rawat = ? 
          LIMIT 1";

$stmt = mysqli_prepare($koneksi, $query);
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $no_rawat);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    if ($row = mysqli_fetch_assoc($res)) {
        echo json_encode([
            'status' => 'success',
            'found' => true,
            'data' => $row
        ]);
    } else {
        // Cek apakah ada diagnosa awal / keluhan dari data rawat inap / pemeriksaan terakhir untuk prefill
        $query_prefill = "SELECT kamar_inap.diagnosa_awal 
                          FROM kamar_inap 
                          WHERE kamar_inap.no_rawat = ? 
                          LIMIT 1";
        $stmt2 = mysqli_prepare($koneksi, $query_prefill);
        $diagnosa_awal = '';
        if ($stmt2) {
            mysqli_stmt_bind_param($stmt2, "s", $no_rawat);
            mysqli_stmt_execute($stmt2);
            $res2 = mysqli_stmt_get_result($stmt2);
            if ($row2 = mysqli_fetch_assoc($res2)) {
                $diagnosa_awal = $row2['diagnosa_awal'] ?? '';
            }
            mysqli_stmt_close($stmt2);
        }

        echo json_encode([
            'status' => 'success',
            'found' => false,
            'message' => 'Belum ada data resume rawat inap.',
            'prefill' => [
                'diagnosa_awal' => $diagnosa_awal
            ]
        ]);
    }
    mysqli_stmt_close($stmt);
} else {
    echo json_encode([
        'status' => 'error',
        'message' => 'Query error: ' . mysqli_error($koneksi)
    ]);
}
exit();
