<?php
require_once 'auth.php';

header('Content-Type: application/json; charset=utf-8');

$no_rawat = isset($_GET['no_rawat']) ? trim($_GET['no_rawat']) : '';

if (empty($no_rawat)) {
    echo json_encode(['status' => 'error', 'message' => 'No. Rawat tidak valid.']);
    exit();
}

// Ambil riwayat SOAPIE terakhir untuk no_rawat ini
$query = "SELECT 
            pemeriksaan_ranap.*,
            COALESCE(dokter.nm_dokter, pegawai.nama, pemeriksaan_ranap.nip) AS nama_petugas
          FROM pemeriksaan_ranap
          LEFT JOIN dokter ON pemeriksaan_ranap.nip = dokter.kd_dokter
          LEFT JOIN pegawai ON pemeriksaan_ranap.nip = pegawai.nik
          WHERE pemeriksaan_ranap.no_rawat = ?
          ORDER BY pemeriksaan_ranap.tgl_perawatan DESC, pemeriksaan_ranap.jam_rawat DESC
          LIMIT 1";

$stmt = mysqli_prepare($koneksi, $query);

if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $no_rawat);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    if ($row = mysqli_fetch_assoc($result)) {
        echo json_encode([
            'status' => 'success',
            'found' => true,
            'data' => [
                'no_rawat'       => $row['no_rawat'],
                'tgl_perawatan'  => $row['tgl_perawatan'],
                'jam_rawat'      => $row['jam_rawat'],
                'suhu_tubuh'     => $row['suhu_tubuh'],
                'tensi'          => $row['tensi'],
                'nadi'           => $row['nadi'],
                'respirasi'      => $row['respirasi'],
                'tinggi'         => $row['tinggi'],
                'berat'          => $row['berat'],
                'spo2'           => $row['spo2'],
                'gcs'            => $row['gcs'],
                'kesadaran'      => $row['kesadaran'],
                'keluhan'        => $row['keluhan'],
                'pemeriksaan'    => $row['pemeriksaan'],
                'alergi'         => $row['alergi'],
                'penilaian'      => $row['penilaian'],
                'rtl'            => $row['rtl'],
                'instruksi'      => $row['instruksi'],
                'evaluasi'       => $row['evaluasi'],
                'nip'            => $row['nip'],
                'nama_petugas'   => $row['nama_petugas']
            ]
        ]);
    } else {
        echo json_encode([
            'status' => 'success',
            'found' => false,
            'message' => 'Belum ada catatan SOAPIE sebelumnya.'
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
