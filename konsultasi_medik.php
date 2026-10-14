<?php
require_once 'auth.php';

$pesan_sukses = '';
$pesan_error = '';

// Proses Simpan / Update Jawaban Konsultasi Medik ke tabel jawaban_konsultasi_medik
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['simpan_jawaban_medik'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $pesan_error = "Token keamanan tidak valid. Silakan muat ulang halaman.";
    } else {
        $post_no_permintaan  = mysqli_real_escape_string($koneksi, trim($_POST['no_permintaan'] ?? ''));
        $post_diagnosa_kerja = mysqli_real_escape_string($koneksi, trim($_POST['diagnosa_kerja'] ?? ''));
        $post_uraian_jawaban = mysqli_real_escape_string($koneksi, trim($_POST['uraian_jawaban'] ?? ''));

        // Batasi panjang karakter sesuai struktur tabel database jawaban_konsultasi_medik
        $post_diagnosa_kerja = mb_substr($post_diagnosa_kerja, 0, 200);
        $post_uraian_jawaban = mb_substr($post_uraian_jawaban, 0, 800);

        if (empty($post_no_permintaan)) {
            $pesan_error = "No. Permintaan konsultasi tidak valid.";
        } else if (empty($post_uraian_jawaban)) {
            $pesan_error = "Uraian jawaban konsultasi medik tidak boleh kosong.";
        } else {
            // Verifikasi hak akses: pastikan konsultasi ada & jika bukan super admin, pastikan ditujukan ke dokter login ini
            $stmt_cek = mysqli_prepare($koneksi, "SELECT kd_dokter_dikonsuli FROM konsultasi_medik WHERE no_permintaan = ?");
            if ($stmt_cek) {
                mysqli_stmt_bind_param($stmt_cek, "s", $post_no_permintaan);
                mysqli_stmt_execute($stmt_cek);
                $res_cek = mysqli_stmt_get_result($stmt_cek);
                $row_cek = mysqli_fetch_assoc($res_cek);
                mysqli_stmt_close($stmt_cek);

                if (!$row_cek) {
                    $pesan_error = "Data konsultasi medik No. $post_no_permintaan tidak ditemukan.";
                } else if (!$is_super_admin && (!empty($kd_dokter) && $row_cek['kd_dokter_dikonsuli'] !== $kd_dokter)) {
                    $pesan_error = "Anda tidak memiliki hak akses untuk menjawab konsultasi medik ini.";
                } else {
                    $tgl_sekarang = date('Y-m-d H:i:s');
                    $stmt_save = mysqli_prepare($koneksi, "
                        INSERT INTO jawaban_konsultasi_medik (no_permintaan, tanggal, diagnosa_kerja, uraian_jawaban)
                        VALUES (?, ?, ?, ?)
                        ON DUPLICATE KEY UPDATE
                            tanggal = VALUES(tanggal),
                            diagnosa_kerja = VALUES(diagnosa_kerja),
                            uraian_jawaban = VALUES(uraian_jawaban)
                    ");

                    if ($stmt_save) {
                        mysqli_stmt_bind_param($stmt_save, "ssss", $post_no_permintaan, $tgl_sekarang, $post_diagnosa_kerja, $post_uraian_jawaban);
                        if (mysqli_stmt_execute($stmt_save)) {
                            $pesan_sukses = "Jawaban konsultasi medik No. $post_no_permintaan berhasil disimpan!";
                        } else {
                            $pesan_error = "Gagal menyimpan jawaban: " . mysqli_stmt_error($stmt_save);
                        }
                        mysqli_stmt_close($stmt_save);
                    } else {
                        $pesan_error = "Gagal menyiapkan query simpan: " . mysqli_error($koneksi);
                    }
                }
            } else {
                $pesan_error = "Gagal memeriksa data konsultasi: " . mysqli_error($koneksi);
            }
        }
    }
}

// Filter Rentang Tanggal (Default: 7 hari terakhir)
$tgl_default_awal = date('Y-m-d', strtotime('-7 days'));
$tgl_default_akhir = date('Y-m-d');

$tgl_awal = isset($_GET['tgl_awal']) && !empty($_GET['tgl_awal']) ? trim($_GET['tgl_awal']) : $tgl_default_awal;
$tgl_akhir = isset($_GET['tgl_akhir']) && !empty($_GET['tgl_akhir']) ? trim($_GET['tgl_akhir']) : $tgl_default_akhir;

if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $tgl_awal)) $tgl_awal = $tgl_default_awal;
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $tgl_akhir)) $tgl_akhir = $tgl_default_akhir;
if ($tgl_awal > $tgl_akhir) {
    $temp = $tgl_awal;
    $tgl_awal = $tgl_akhir;
    $tgl_akhir = $temp;
}

// Filter Status Jawab & Pencarian
$filter_status = isset($_GET['status']) ? trim($_GET['status']) : 'all'; // all, belum, sudah
$keyword = isset($_GET['keyword']) ? trim($_GET['keyword']) : '';

// Query Konsultasi Medik berelasi dengan jawaban_konsultasi_medik pada field no_permintaan
$data_konsul = array();

$sql = "SELECT km.no_permintaan, km.no_rawat, km.tanggal as tgl_konsul,
               km.jenis_permintaan, km.kd_dokter, km.kd_dokter_dikonsuli,
               km.diagnosa_kerja as diagnosa_pemohon, km.uraian_konsultasi,
               jkm.tanggal as tgl_jawaban, jkm.diagnosa_kerja as diagnosa_jawaban, jkm.uraian_jawaban,
               p.nm_pasien, rp.no_rkm_medis, pj.png_jawab,
               dok_pemohon.nm_dokter as nm_dokter_pemohon,
               dok_tujuan.nm_dokter as nm_dokter_tujuan,
               COALESCE(ki.diagnosa_awal, '-') as diagnosa_awal,
               COALESCE(b.nm_bangsal, poli.nm_poli, '-') as lokasi,
               COALESCE(k.kd_kamar, '') as kd_kamar,
               CASE 
                   WHEN jkm.no_permintaan IS NOT NULL THEN 1 
                   ELSE 0 
               END as sudah_dijawab
        FROM konsultasi_medik km
        LEFT JOIN jawaban_konsultasi_medik jkm ON km.no_permintaan = jkm.no_permintaan
        INNER JOIN reg_periksa rp ON km.no_rawat = rp.no_rawat
        INNER JOIN pasien p ON rp.no_rkm_medis = p.no_rkm_medis
        LEFT JOIN penjab pj ON rp.kd_pj = pj.kd_pj
        LEFT JOIN dokter dok_pemohon ON km.kd_dokter = dok_pemohon.kd_dokter
        LEFT JOIN dokter dok_tujuan ON km.kd_dokter_dikonsuli = dok_tujuan.kd_dokter
        LEFT JOIN kamar_inap ki ON km.no_rawat = ki.no_rawat AND ki.stts_pulang = '-'
        LEFT JOIN kamar k ON ki.kd_kamar = k.kd_kamar
        LEFT JOIN bangsal b ON k.kd_bangsal = b.kd_bangsal
        LEFT JOIN poliklinik poli ON rp.kd_poli = poli.kd_poli
        WHERE DATE(km.tanggal) BETWEEN '$tgl_awal' AND '$tgl_akhir'";

if ($is_super_admin) {
    // Super admin melihat semua data pada rentang tanggal
} else {
    // Dokter yang sedang login (sebagai dokter yang dikonsuli)
    $sql .= " AND km.kd_dokter_dikonsuli = '" . mysqli_real_escape_string($koneksi, $kd_dokter) . "'";
}

// Prioritas: Belum Dijawab tampil paling atas (sudah_dijawab ASC), lalu urut tanggal terbaru (km.tanggal DESC)
$sql .= " ORDER BY sudah_dijawab ASC, km.tanggal DESC LIMIT 300";

$res_konsul = mysqli_query($koneksi, $sql);
$total_konsul = 0;
$total_belum = 0;
$total_sudah = 0;

if ($res_konsul) {
    while ($row = mysqli_fetch_assoc($res_konsul)) {
        $total_konsul++;
        if ($row['sudah_dijawab']) {
            $total_sudah++;
        } else {
            $total_belum++;
        }
        $data_konsul[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Konsultasi Medik - <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        :root {
            --primary: #e11d48;
            --primary-dark: #be123c;
            --primary-light: #ffe4e6;
            --primary-subtle: #fff1f2;
            --teal: #0d9488;
            --success: #16a34a;
            --warning: #ea580c;
            --info: #0284c7;
            --indigo: #4f46e5;
            --dark: #0f172a;
            --gray: #64748b;
            --card-border: #e2e8f0;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
            --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1);
            --radius: 12px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f8fafc;
            color: var(--dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.5;
        }

        /* Top Navigation */
        .top-navbar {
            background: linear-gradient(135deg, #e11d48 0%, #be123c 100%);
            color: white;
            padding: 12px 16px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(225, 29, 72, 0.25);
        }

        .navbar-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .nav-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .btn-back {
            background: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            text-decoration: none;
            transition: background 0.2s;
        }
        .btn-back:hover {
            background: rgba(255, 255, 255, 0.3);
        }

        .nav-title h1 {
            font-size: 17px;
            font-weight: 700;
            letter-spacing: -0.3px;
        }
        .nav-title p {
            font-size: 11px;
            opacity: 0.9;
        }

        .nav-right {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .clock-badge {
            background: rgba(255, 255, 255, 0.2);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }

        /* Main Container */
        .main-container {
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
            padding: 16px;
            flex: 1;
        }

        /* Alert notifications */
        .alert-box {
            padding: 12px 16px;
            border-radius: var(--radius);
            margin-bottom: 16px;
            font-size: 14px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .alert-box.success {
            background-color: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        .alert-box.error {
            background-color: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }

        /* Stat Cards */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }

        .stat-card {
            background: white;
            border-radius: var(--radius);
            padding: 14px 16px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
            overflow: hidden;
        }
        .stat-card:hover {
            box-shadow: var(--shadow-md);
        }
        .stat-card.active {
            outline: 2px solid var(--primary-dark);
            background: var(--primary-subtle);
        }

        .stat-card .stat-label {
            font-size: 12px;
            color: var(--gray);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .stat-card .stat-val {
            font-size: 24px;
            font-weight: 800;
            margin-top: 4px;
            color: var(--dark);
        }

        .stat-total .stat-val { color: var(--primary); }
        .stat-belum .stat-val { color: #dc2626; }
        .stat-sudah .stat-val { color: #16a34a; }

        /* Date Range Filter Section */
        .date-filter-section {
            background: white;
            border-radius: var(--radius);
            padding: 12px 14px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            margin-bottom: 14px;
        }

        .date-filter-form {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }

        .date-inputs {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }

        .date-field {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 700;
            color: #475569;
        }

        .date-field input[type="date"] {
            padding: 6px 10px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 12px;
            color: #1e293b;
            font-family: inherit;
            background: white;
            outline: none;
            transition: border-color 0.2s;
        }

        .date-field input[type="date"]:focus {
            border-color: var(--primary);
        }

        .btn-filter-submit {
            background: var(--primary);
            color: white;
            border: none;
            padding: 7px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn-filter-submit:hover {
            opacity: 0.9;
        }

        .date-preset-buttons {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 6px;
        }

        .btn-preset {
            background: #f1f5f9;
            color: #475569;
            border: 1px solid #e2e8f0;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.15s;
        }
        .btn-preset:hover {
            background: #e2e8f0;
            color: #0f172a;
        }
        .btn-preset.active {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        /* Filter & Search Bar */
        .filter-section {
            background: white;
            border-radius: var(--radius);
            padding: 12px 14px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            margin-bottom: 16px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
            justify-content: space-between;
        }

        .search-box {
            flex: 1;
            min-width: 240px;
            position: relative;
        }
        .search-box input {
            width: 100%;
            padding: 9px 12px 9px 36px;
            border-radius: 8px;
            border: 1px solid #cbd5e1;
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-box input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(225, 29, 72, 0.15);
        }
        .search-box svg {
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: #94a3b8;
        }

        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .select-jenis {
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid #cbd5e1;
            font-size: 12px;
            font-weight: 600;
            color: #334155;
            outline: none;
            background: white;
            cursor: pointer;
        }
        .select-jenis:focus {
            border-color: var(--primary);
        }

        .view-switch {
            display: flex;
            background: #f1f5f9;
            border-radius: 8px;
            padding: 2px;
        }
        .view-btn {
            border: none;
            background: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: #64748b;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .view-btn.active {
            background: white;
            color: var(--primary);
            box-shadow: 0 1px 2px rgba(0,0,0,0.06);
        }

        /* Mobile Card View */
        .cards-container {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .konsul-card {
            background: white;
            border-radius: var(--radius);
            padding: 16px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            transition: transform 0.15s, box-shadow 0.15s;
        }
        .konsul-card:hover {
            box-shadow: var(--shadow-md);
        }

        .card-header-row {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 8px;
            margin-bottom: 8px;
        }

        .card-title-group {
            flex: 1;
        }
        .card-no-permintaan {
            font-size: 11px;
            font-family: monospace;
            font-weight: 700;
            color: var(--primary);
        }
        .card-patient-name {
            font-size: 15px;
            font-weight: 800;
            color: #0f172a;
            margin-top: 2px;
        }

        .badge-status {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            white-space: nowrap;
        }
        .badge-belum {
            background: #fee2e2;
            color: #b91c1c;
        }
        .badge-sudah {
            background: #dcfce7;
            color: #15803d;
        }

        /* Badge Jenis Permintaan */
        .badge-jenis {
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 6px;
            margin-top: 4px;
        }
        .badge-jenis.konsultasi { background: #e0e7ff; color: #3730a3; }
        .badge-jenis.evaluasi { background: #e0f2fe; color: #0369a1; }
        .badge-jenis.rawat-bersama { background: #f3e8ff; color: #6b21a8; }
        .badge-jenis.alih-rawat { background: #fef3c7; color: #92400e; }
        .badge-jenis.pre-post-operasi { background: #ffe4e6; color: #9f1239; }

        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px 12px;
            font-size: 13px;
            margin: 10px 0;
            padding: 10px 0;
            border-top: 1px dashed #e2e8f0;
            border-bottom: 1px dashed #e2e8f0;
        }
        .info-cell {
            display: flex;
            flex-direction: column;
        }
        .info-cell-label {
            font-size: 11px;
            color: var(--gray);
            margin-bottom: 2px;
        }
        .info-cell-val {
            font-weight: 600;
            color: #334155;
            word-break: break-word;
        }

        /* Uraian Box Card */
        .konsul-preview-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 12px;
            font-size: 12px;
            line-height: 1.5;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .preview-box-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            font-weight: 700;
            color: #475569;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px dashed #cbd5e1;
            padding-bottom: 4px;
        }
        .diagnosa-preview {
            color: #0f172a;
            font-weight: 700;
        }
        .uraian-preview {
            color: #334155;
            white-space: pre-line;
        }

        /* Jawaban Dokter Box in Card */
        .dokter-answer-box {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-left: 4px solid #16a34a;
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 12px;
            font-size: 12px;
            line-height: 1.5;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .answer-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            padding-bottom: 4px;
            border-bottom: 1px dashed #bbf7d0;
        }
        .answer-badge {
            font-size: 11px;
            font-weight: 800;
            color: #166534;
            text-transform: uppercase;
        }
        .answer-time {
            font-size: 11px;
            color: #15803d;
            font-weight: 600;
        }
        .answer-field {
            font-size: 12px;
            color: #1e293b;
        }
        .field-label {
            font-weight: 700;
            color: #166534;
            margin-right: 4px;
        }

        .btn-action-jawab {
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 10px 16px;
            border-radius: 8px;
            border: none;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-action-jawab.belum {
            background: linear-gradient(135deg, #e11d48 0%, #be123c 100%);
            color: white;
            box-shadow: 0 2px 4px rgba(225, 29, 72, 0.3);
        }
        .btn-action-jawab.sudah {
            background: #f0fdf4;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        .btn-action-jawab:hover {
            opacity: 0.95;
        }

        /* Desktop Table View */
        .table-responsive {
            background: white;
            border-radius: var(--radius);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            overflow-x: auto;
            display: none;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }
        table th {
            background: #f8fafc;
            color: #475569;
            font-weight: 700;
            padding: 12px 14px;
            border-bottom: 2px solid #e2e8f0;
            white-space: nowrap;
        }
        table td {
            padding: 12px 14px;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: middle;
        }
        table tbody tr:hover {
            background-color: #f8fafc;
        }
        .btn-table-jawab {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            border: none;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            white-space: nowrap;
        }
        .btn-table-jawab.belum {
            background: var(--primary);
            color: white;
        }
        .btn-table-jawab.sudah {
            background: #dcfce7;
            color: #15803d;
            border: 1px solid #bbf7d0;
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow-y: auto;
            background-color: rgba(15, 23, 42, 0.65);
            backdrop-filter: blur(4px);
            padding: 12px;
        }

        .modal-content {
            background-color: #ffffff;
            margin: 20px auto;
            padding: 24px;
            width: 100%;
            max-width: 820px;
            border-radius: 16px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
            position: relative;
            animation: modalFadeIn 0.25s ease-out;
        }

        @keyframes modalFadeIn {
            from { opacity: 0; transform: translateY(-16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .modal-close {
            position: absolute;
            top: 18px;
            right: 18px;
            width: 32px;
            height: 32px;
            background: #f1f5f9;
            color: #64748b;
            border: none;
            border-radius: 50%;
            font-size: 20px;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        .modal-close:hover {
            background: #fee2e2;
            color: #ef4444;
        }

        .modal-header-title {
            font-size: 18px;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 4px;
        }

        .patient-summary-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 12px 14px;
            margin: 12px 0 14px;
            font-size: 13px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px 20px;
            align-items: center;
        }
        .patient-summary-box strong {
            color: #0f172a;
        }

        .last-answered-info {
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
            color: #065f46;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 12px;
            margin-bottom: 14px;
        }

        .section-label {
            font-size: 14px;
            font-weight: 700;
            color: #334155;
            padding-bottom: 6px;
            border-bottom: 2px solid #cbd5e1;
            margin: 16px 0 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 6px;
        }
        .doctor-section-label {
            border-bottom-color: #86efac;
        }
        .table-target-tag {
            font-size: 11px;
            font-weight: 600;
            font-family: monospace;
            background: #dcfce7;
            color: #166534;
            padding: 2px 8px;
            border-radius: 6px;
        }

        /* Detail Permintaan Konsultasi Card */
        .konsul-detail-box {
            background: #fff1f2;
            border: 1px solid #fecdd3;
            border-radius: 10px;
            padding: 12px 16px;
            margin-bottom: 16px;
            font-size: 13px;
        }
        .detail-row {
            margin-bottom: 8px;
        }
        .detail-row:last-child {
            margin-bottom: 0;
        }
        .detail-title {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: #9f1239;
            margin-bottom: 2px;
        }
        .detail-content {
            color: #1e293b;
            white-space: pre-wrap;
            word-break: break-word;
        }

        /* Form Fields */
        .form-field {
            display: flex;
            flex-direction: column;
            margin-bottom: 12px;
        }
        .field-label-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }
        .form-field label {
            font-size: 12px;
            font-weight: 700;
            color: #475569;
        }
        .field-help-text, .char-counter {
            font-size: 11px;
            color: var(--gray);
            font-weight: 500;
        }
        .form-field textarea, .form-field input {
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid #cbd5e1;
            font-family: inherit;
            font-size: 13px;
            outline: none;
            background: white;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-field textarea:focus, .form-field input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(225, 29, 72, 0.15);
        }
        .form-field textarea {
            resize: vertical;
            min-height: 80px;
        }

        /* Quick Templates */
        .quick-tags-container {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 6px;
            margin-top: 6px;
        }
        .quick-tags-label {
            font-size: 11px;
            color: var(--gray);
            font-weight: 600;
        }
        .tag-pill {
            background: #f1f5f9;
            color: #334155;
            border: 1px solid #cbd5e1;
            padding: 3px 8px;
            border-radius: 14px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }
        .tag-pill:hover {
            background: #e2e8f0;
            color: #0f172a;
            border-color: #94a3b8;
        }

        .btn-copy-diag {
            background: #e0f2fe;
            color: #0284c7;
            border: 1px solid #bae6fd;
            border-radius: 4px;
            padding: 1px 6px;
            font-size: 10px;
            font-weight: 700;
            cursor: pointer;
            margin-left: 6px;
        }
        .btn-copy-diag:hover {
            background: #bae6fd;
        }

        .modal-action-footer {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid #e2e8f0;
        }

        .btn-cancel {
            background: #f1f5f9;
            color: #475569;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
        }
        .btn-cancel:hover {
            background: #e2e8f0;
        }

        .btn-submit {
            background: linear-gradient(135deg, #16a34a 0%, #15803d 100%);
            color: white;
            border: none;
            padding: 10px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(22, 163, 74, 0.3);
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .btn-submit:hover {
            opacity: 0.95;
        }

        .empty-box {
            background: white;
            border-radius: var(--radius);
            padding: 40px 20px;
            text-align: center;
            color: var(--gray);
            border: 1px dashed #cbd5e1;
        }

        footer {
            margin-top: auto;
            text-align: center;
            padding: 20px 16px;
            font-size: 12px;
            color: var(--gray);
            border-top: 1px solid #e2e8f0;
            background: white;
        }

        @media (min-width: 768px) {
            .table-responsive.show-desktop {
                display: block;
            }
            .cards-container.hide-desktop {
                display: none;
            }
        }
    </style>
</head>
<body>

<!-- Header Navbar -->
<header class="top-navbar">
    <div class="navbar-content">
        <div class="nav-left">
            <a href="index.php" class="btn-back" title="Kembali ke Menu Utama">
                <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>
            </a>
            <div class="nav-title">
                <h1>Konsultasi Medik (Antar Dokter)</h1>
                <p><?php echo htmlspecialchars($nama_pegawai); ?> <?php echo $is_super_admin ? '(Super Admin)' : '(Dokter DPJP / Spesialis)'; ?></p>
            </div>
        </div>
        <div class="nav-right">
            <span class="clock-badge" id="liveClock"><?php echo date('H:i'); ?></span>
        </div>
    </div>
</header>

<main class="main-container">

    <!-- Notifikasi Sukses / Error -->
    <?php if (!empty($pesan_sukses)): ?>
        <div class="alert-box success">
            <span>✅</span> <?php echo htmlspecialchars($pesan_sukses); ?>
        </div>
    <?php endif; ?>
    <?php if (!empty($pesan_error)): ?>
        <div class="alert-box error">
            <span>⚠️</span> <?php echo htmlspecialchars($pesan_error); ?>
        </div>
    <?php endif; ?>

    <!-- Stat Cards Rekap -->
    <div class="stat-grid">
        <div class="stat-card stat-total active" onclick="filterByStatus('all')">
            <div class="stat-label">Total Konsultasi</div>
            <div class="stat-val"><?php echo $total_konsul; ?></div>
        </div>
        <div class="stat-card stat-belum" onclick="filterByStatus('belum')">
            <div class="stat-label">Belum Dijawab</div>
            <div class="stat-val"><?php echo $total_belum; ?></div>
        </div>
        <div class="stat-card stat-sudah" onclick="filterByStatus('sudah')">
            <div class="stat-label">Sudah Dijawab</div>
            <div class="stat-val"><?php echo $total_sudah; ?></div>
        </div>
    </div>

    <!-- Filter Rentang Tanggal Toolbar -->
    <div class="date-filter-section">
        <form method="GET" action="" class="date-filter-form" id="dateFilterForm">
            <input type="hidden" name="status" value="<?php echo htmlspecialchars($filter_status); ?>">
            <div class="date-inputs">
                <div class="date-field">
                    <label for="tglAwal">📅 Periode:</label>
                    <input type="date" name="tgl_awal" id="tglAwal" value="<?php echo htmlspecialchars($tgl_awal); ?>" onchange="document.getElementById('dateFilterForm').submit()">
                </div>
                <div class="date-field">
                    <span>s/d</span>
                    <input type="date" name="tgl_akhir" id="tglAkhir" value="<?php echo htmlspecialchars($tgl_akhir); ?>" onchange="document.getElementById('dateFilterForm').submit()">
                </div>
                <button type="submit" class="btn-filter-submit" title="Terapkan Filter Tanggal">
                    <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M21 21l-4.35-4.35M11 19a8 8 0 100-16 8 8 0 000 16z"/></svg>
                    <span>Terapkan</span>
                </button>
            </div>
            
            <!-- Quick Date Preset Buttons -->
            <div class="date-preset-buttons">
                <button type="button" class="btn-preset <?php echo ($tgl_awal === date('Y-m-d') && $tgl_akhir === date('Y-m-d')) ? 'active' : ''; ?>" onclick="setDatePreset('hari_ini')">Hari Ini</button>
                <button type="button" class="btn-preset <?php echo ($tgl_awal === date('Y-m-d', strtotime('-7 days')) && $tgl_akhir === date('Y-m-d')) ? 'active' : ''; ?>" onclick="setDatePreset('7_hari')">7 Hari Terakhir</button>
                <button type="button" class="btn-preset <?php echo ($tgl_awal === date('Y-m-d', strtotime('-30 days')) && $tgl_akhir === date('Y-m-d')) ? 'active' : ''; ?>" onclick="setDatePreset('30_hari')">30 Hari Terakhir</button>
                <button type="button" class="btn-preset <?php echo ($tgl_awal === date('Y-m-01') && $tgl_akhir === date('Y-m-t')) ? 'active' : ''; ?>" onclick="setDatePreset('bulan_ini')">Bulan Ini</button>
            </div>
        </form>
    </div>

    <!-- Filter & Search Toolbar -->
    <div class="filter-section">
        <div class="search-box">
            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
            <input type="text" id="searchInput" placeholder="Cari pasien, no rawat, dokter pengirim, diagnosa, atau uraian..." oninput="filterData()">
        </div>

        <div class="filter-group">
            <select class="select-jenis" id="selectJenisFilter" onchange="filterData()">
                <option value="all">Semua Jenis Permintaan</option>
                <option value="konsultasi">Konsultasi</option>
                <option value="evaluasi">Evaluasi</option>
                <option value="rawat bersama">Rawat Bersama</option>
                <option value="alih rawat">Alih Rawat</option>
                <option value="pre/post operasi">Pre/Post Operasi</option>
            </select>

            <div class="view-switch">
                <button type="button" class="view-btn" id="btnCardView" onclick="setViewMode('card')">
                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    Kartu
                </button>
                <button type="button" class="view-btn active" id="btnTableView" onclick="setViewMode('table')">
                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
                    Tabel
                </button>
            </div>
        </div>
    </div>

    <?php if (!empty($data_konsul)): ?>
        <!-- Mobile Card List -->
        <div class="cards-container hide-desktop" id="konsulCards">
            <?php foreach ($data_konsul as $k): 
                $status_key = $k['sudah_dijawab'] ? 'sudah' : 'belum';
                $badge_class = $k['sudah_dijawab'] ? 'badge-sudah' : 'badge-belum';
                $status_text = $k['sudah_dijawab'] ? 'Sudah Dijawab' : 'Belum Dijawab';
                $jenis_class = strtolower(str_replace(['/', ' '], '-', $k['jenis_permintaan'] ?? 'konsultasi'));
                $json_konsul = htmlspecialchars(json_encode($k), ENT_QUOTES, 'UTF-8');
            ?>
                <div class="konsul-card" 
                     data-status="<?php echo $status_key; ?>" 
                     data-jenis="<?php echo strtolower($k['jenis_permintaan'] ?? ''); ?>"
                     data-search="<?php echo strtolower($k['nm_pasien'] . ' ' . $k['no_rkm_medis'] . ' ' . $k['no_rawat'] . ' ' . $k['no_permintaan'] . ' ' . $k['lokasi'] . ' ' . $k['nm_dokter_pemohon'] . ' ' . $k['nm_dokter_tujuan'] . ' ' . $k['diagnosa_pemohon'] . ' ' . $k['uraian_konsultasi'] . ' ' . ($k['diagnosa_jawaban'] ?? '') . ' ' . ($k['uraian_jawaban'] ?? '')); ?>">
                    
                    <div class="card-header-row">
                        <div class="card-title-group">
                            <div class="card-no-permintaan">#<?php echo htmlspecialchars($k['no_permintaan']); ?> &bull; 🕒 <?php echo date('d/m/Y H:i', strtotime($k['tgl_konsul'])); ?></div>
                            <div class="card-patient-name"><?php echo htmlspecialchars($k['nm_pasien']); ?></div>
                            <span class="badge-jenis <?php echo $jenis_class; ?>"><?php echo htmlspecialchars($k['jenis_permintaan']); ?></span>
                        </div>
                        <span class="badge-status <?php echo $badge_class; ?>"><?php echo $status_text; ?></span>
                    </div>

                    <div class="info-grid">
                        <div class="info-cell">
                            <span class="info-cell-label">No. Rawat / RM</span>
                            <span class="info-cell-val"><?php echo htmlspecialchars($k['no_rawat']); ?> (<?php echo htmlspecialchars($k['no_rkm_medis']); ?>)</span>
                        </div>
                        <div class="info-cell">
                            <span class="info-cell-label">Lokasi / Kamar</span>
                            <span class="info-cell-val">🏥 <?php echo htmlspecialchars($k['lokasi']); ?> <?php echo !empty($k['kd_kamar']) ? '(' . htmlspecialchars($k['kd_kamar']) . ')' : ''; ?></span>
                        </div>
                        <div class="info-cell">
                            <span class="info-cell-label">Dokter Pemohon</span>
                            <span class="info-cell-val">👨‍⚕️ <?php echo htmlspecialchars($k['nm_dokter_pemohon'] ?? $k['kd_dokter']); ?></span>
                        </div>
                        <div class="info-cell">
                            <span class="info-cell-label">Dokter Yang Dikonsuli</span>
                            <span class="info-cell-val">🩺 <?php echo htmlspecialchars($k['nm_dokter_tujuan'] ?? $k['kd_dokter_dikonsuli']); ?></span>
                        </div>
                    </div>

                    <!-- Uraian Permintaan Konsultasi -->
                    <div class="konsul-preview-box">
                        <div class="preview-box-header">
                            <span>Permintaan Konsultasi Medik</span>
                            <span style="font-size:10px; color:var(--primary); font-weight:700;">DARI: <?php echo htmlspecialchars($k['nm_dokter_pemohon']); ?></span>
                        </div>
                        <div>
                            <span style="font-size:11px; color:var(--gray); font-weight:700;">Diagnosa Kerja Pemohon:</span>
                            <div class="diagnosa-preview"><?php echo htmlspecialchars($k['diagnosa_pemohon'] ?: '-'); ?></div>
                        </div>
                        <div>
                            <span style="font-size:11px; color:var(--gray); font-weight:700;">Uraian Konsultasi:</span>
                            <div class="uraian-preview"><?php echo htmlspecialchars(mb_strimwidth($k['uraian_konsultasi'] ?? '-', 0, 160, '...')); ?></div>
                        </div>
                    </div>

                    <!-- Jawaban Dokter jika sudah dijawab -->
                    <?php if ($k['sudah_dijawab']): ?>
                        <div class="dokter-answer-box">
                            <div class="answer-header">
                                <span class="answer-badge">🩺 Jawaban Konsultasi Medik</span>
                                <span class="answer-time">🕒 <?php echo date('d/m/Y H:i', strtotime($k['tgl_jawaban'])); ?></span>
                            </div>
                            <?php if (!empty($k['diagnosa_jawaban'])): ?>
                                <div class="answer-field">
                                    <span class="field-label">Diagnosa Penjawab:</span>
                                    <span><?php echo htmlspecialchars($k['diagnosa_jawaban']); ?></span>
                                </div>
                            <?php endif; ?>
                            <div class="answer-field">
                                <span class="field-label">Jawaban & Instruksi:</span>
                                <span><?php echo nl2br(htmlspecialchars($k['uraian_jawaban'])); ?></span>
                            </div>
                        </div>
                    <?php endif; ?>

                    <button type="button" class="btn-action-jawab <?php echo $status_key; ?>" onclick='bukaModalJawab(<?php echo $json_konsul; ?>)'>
                        <?php if ($k['sudah_dijawab']): ?>
                            <span>✏️ Ubah / Perbarui Jawaban Konsultasi</span>
                        <?php else: ?>
                            <span>💬 Jawab Konsultasi Medik</span>
                        <?php endif; ?>
                    </button>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Desktop Table View -->
        <div class="table-responsive show-desktop" id="konsulTable">
            <table>
                <thead>
                    <tr>
                        <th style="width: 35px;">No</th>
                        <th>Waktu & No. Konsul</th>
                        <th>No. Rawat / RM</th>
                        <th>Pasien</th>
                        <th>Lokasi</th>
                        <th>Jenis & Pemohon</th>
                        <th>Diagnosa & Permintaan Konsultasi</th>
                        <th>Jawaban Dokter Dikonsuli</th>
                        <th>Status</th>
                        <th style="text-align:center; width: 120px;">Aksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $no = 1;
                    foreach ($data_konsul as $k): 
                        $status_key = $k['sudah_dijawab'] ? 'sudah' : 'belum';
                        $badge_class = $k['sudah_dijawab'] ? 'badge-sudah' : 'badge-belum';
                        $status_text = $k['sudah_dijawab'] ? 'Sudah Dijawab' : 'Belum Dijawab';
                        $jenis_class = strtolower(str_replace(['/', ' '], '-', $k['jenis_permintaan'] ?? 'konsultasi'));
                        $json_konsul = htmlspecialchars(json_encode($k), ENT_QUOTES, 'UTF-8');
                    ?>
                        <tr data-status="<?php echo $status_key; ?>" 
                            data-jenis="<?php echo strtolower($k['jenis_permintaan'] ?? ''); ?>"
                            data-search="<?php echo strtolower($k['nm_pasien'] . ' ' . $k['no_rkm_medis'] . ' ' . $k['no_rawat'] . ' ' . $k['no_permintaan'] . ' ' . $k['lokasi'] . ' ' . $k['nm_dokter_pemohon'] . ' ' . $k['nm_dokter_tujuan'] . ' ' . $k['diagnosa_pemohon'] . ' ' . $k['uraian_konsultasi'] . ' ' . ($k['diagnosa_jawaban'] ?? '') . ' ' . ($k['uraian_jawaban'] ?? '')); ?>">
                            <td><?php echo $no++; ?></td>
                            <td>
                                <strong><?php echo date('d/m/Y H:i', strtotime($k['tgl_konsul'])); ?></strong><br>
                                <small style="color:var(--gray); font-family:monospace;"><?php echo htmlspecialchars($k['no_permintaan']); ?></small>
                            </td>
                            <td>
                                <strong><?php echo htmlspecialchars($k['no_rawat']); ?></strong><br>
                                <small style="color:var(--gray);">RM: <?php echo htmlspecialchars($k['no_rkm_medis']); ?></small>
                            </td>
                            <td>
                                <strong><?php echo htmlspecialchars($k['nm_pasien']); ?></strong><br>
                                <small style="color:var(--gray);"><?php echo htmlspecialchars($k['png_jawab']); ?></small>
                            </td>
                            <td>
                                <?php echo htmlspecialchars($k['lokasi']); ?>
                                <?php if (!empty($k['kd_kamar'])): ?>
                                    <br><small style="color:var(--gray);">(<?php echo htmlspecialchars($k['kd_kamar']); ?>)</small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="badge-jenis <?php echo $jenis_class; ?>"><?php echo htmlspecialchars($k['jenis_permintaan']); ?></span><br>
                                <small style="color:var(--dark); font-weight:600;">Dari: <?php echo htmlspecialchars($k['nm_dokter_pemohon'] ?? $k['kd_dokter']); ?></small>
                            </td>
                            <td style="max-width: 250px;">
                                <div style="font-size:12px;">
                                    <strong style="color:#0f172a;">Diag:</strong> <?php echo htmlspecialchars(mb_strimwidth($k['diagnosa_pemohon'] ?: '-', 0, 80, '...')); ?><br>
                                    <span style="color:#334155;"><?php echo htmlspecialchars(mb_strimwidth($k['uraian_konsultasi'] ?? '-', 0, 100, '...')); ?></span>
                                </div>
                            </td>
                            <td style="max-width: 250px;">
                                <?php if ($k['sudah_dijawab']): ?>
                                    <div style="font-size:12px;">
                                        <div style="font-size:11px; color:#15803d; font-weight:700; margin-bottom:2px;">
                                            🕒 <?php echo date('d/m/Y H:i', strtotime($k['tgl_jawaban'])); ?>
                                        </div>
                                        <?php if (!empty($k['diagnosa_jawaban'])): ?>
                                            <strong style="color:#0f172a;">Diag:</strong> <?php echo htmlspecialchars(mb_strimwidth($k['diagnosa_jawaban'], 0, 70, '...')); ?><br>
                                        <?php endif; ?>
                                        <span style="color:#166534; font-weight:600;"><?php echo htmlspecialchars(mb_strimwidth($k['uraian_jawaban'], 0, 90, '...')); ?></span>
                                    </div>
                                <?php else: ?>
                                    <span style="color:var(--gray); font-style:italic; font-size:12px;">Menunggu jawaban dokter...</span>
                                <?php endif; ?>
                            </td>
                            <td><span class="badge-status <?php echo $badge_class; ?>"><?php echo $status_text; ?></span></td>
                            <td style="text-align:center;">
                                <button type="button" class="btn-table-jawab <?php echo $status_key; ?>" onclick='bukaModalJawab(<?php echo $json_konsul; ?>)'>
                                    <?php echo $k['sudah_dijawab'] ? '✏️ Edit' : '💬 Jawab'; ?>
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <div class="empty-box">
            <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="margin-bottom:8px; color:#cbd5e1;"><path stroke-linecap="round" stroke-linejoin="round" d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
            <h3 style="font-size: 16px; margin-bottom: 6px; color: #334155;">Tidak Ada Konsultasi Medik</h3>
            <p style="font-size: 13px;">Belum ditemukan data permohonan konsultasi medik yang ditujukan kepada Anda saat ini.</p>
        </div>
    <?php endif; ?>

</main>

<!-- Modal Jawab / Edit Konsultasi Medik -->
<div id="modalJawab" class="modal">
    <div class="modal-content">
        <button type="button" class="modal-close" onclick="tutupModalJawab()">&times;</button>
        
        <h3 class="modal-header-title" id="mdl_header_title">💬 Jawab Konsultasi Medik Antar Dokter</h3>
        <p style="font-size: 12px; color: var(--gray); margin-bottom: 8px;">
            Jawaban dokter akan disimpan ke tabel <code>jawaban_konsultasi_medik</code> dengan relasi <code>no_permintaan</code>
        </p>

        <!-- Ringkasan Pasien & Pengirim -->
        <div class="patient-summary-box">
            <div>Pasien: <strong id="mdl_nama_pasien">-</strong></div>
            <div>No. RM: <strong id="mdl_no_rm">-</strong></div>
            <div>No. Rawat: <strong id="mdl_no_rawat" style="font-family:monospace;">-</strong></div>
            <div>Lokasi: <strong id="mdl_lokasi">-</strong></div>
            <div>Dokter Pemohon: <strong id="mdl_dokter_pemohon">-</strong></div>
            <div>Jenis Permintaan: <strong id="mdl_jenis_permintaan">-</strong></div>
            <div>Waktu Permintaan: <strong id="mdl_tanggal">-</strong></div>
        </div>

        <!-- Banner Info Jika Sudah Pernah Dijawab -->
        <div id="mdl_last_answered_info" class="last-answered-info" style="display:none;"></div>

        <!-- Section 1: Detail Permintaan dari Dokter Pemohon -->
        <div class="section-label">
            <span>📋</span> Permintaan Konsultasi dari Dokter Pemohon
        </div>

        <div class="konsul-detail-box">
            <div class="detail-row">
                <div class="detail-title">Diagnosa Kerja Pemohon:</div>
                <div class="detail-content" id="mdl_diagnosa_pemohon" style="font-weight:700;">-</div>
            </div>
            <div class="detail-row" style="margin-top:8px;">
                <div class="detail-title">Uraian / Permintaan Konsultasi:</div>
                <div class="detail-content" id="mdl_uraian_konsultasi">-</div>
            </div>
        </div>

        <!-- Section 2: Form Jawaban Konsultasi Medik -->
        <form method="POST" action="" id="formKonsulMedik">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="no_permintaan" id="mdl_no_permintaan">

            <div class="section-label doctor-section-label">
                <span>🩺</span> Jawaban Konsultasi Dokter Dikonsuli
                <span class="table-target-tag">Tabel: jawaban_konsultasi_medik</span>
            </div>

            <!-- Diagnosa Kerja Penjawab (Varchar 200) -->
            <div class="form-field">
                <div class="field-label-row">
                    <label for="mdl_diagnosa_jawaban">
                        Diagnosa Kerja (Dokter Penjawab)
                        <button type="button" class="btn-copy-diag" onclick="salinDiagnosaPemohon()" title="Salin diagnosa pemohon">Salin dari Pemohon</button>
                    </label>
                    <span class="char-counter"><span id="charCountDiag">0</span>/200 karakter</span>
                </div>
                <input type="text" name="diagnosa_kerja" id="mdl_diagnosa_jawaban" maxlength="200" placeholder="Diagnosa kerja menurut dokter yang menjawab..." oninput="updateCharCount('mdl_diagnosa_jawaban', 'charCountDiag', 200)" autocomplete="off">
            </div>

            <!-- Uraian Jawaban / Tatalaksana (Varchar 800) -->
            <div class="form-field">
                <div class="field-label-row">
                    <label for="mdl_uraian_jawaban" style="color:#15803d; font-weight:800;">
                        Uraian Jawaban / Rekomendasi Tatalaksana <span style="color:#ef4444;">*</span>
                    </label>
                    <span class="char-counter"><span id="charCountUraian">0</span>/800 karakter</span>
                </div>
                <textarea name="uraian_jawaban" id="mdl_uraian_jawaban" rows="5" maxlength="800" placeholder="Tuliskan rekomendasi medis, instruksi tatalaksana, persetujuan operasi / anestesi, atau arahan alih rawat / rawat bersama..." required oninput="updateCharCount('mdl_uraian_jawaban', 'charCountUraian', 800)" style="border-color:#86efac;"></textarea>
                
                <!-- Quick Template Pills -->
                <div class="quick-tags-container">
                    <span class="quick-tags-label">Template Cepat:</span>
                    <button type="button" class="tag-pill" onclick="appendUraianQuick('ACC OPERASI\nASA 2\nPUASA 6 JAM PREOP')">+ ACC Operasi</button>
                    <button type="button" class="tag-pill" onclick="appendUraianQuick('ACC Operasi dengan toleransi risiko sedang. Siapkan PRC 2 kolf.')">+ ACC OP Toleransi</button>
                    <button type="button" class="tag-pill" onclick="appendUraianQuick('Setuju Rawat Bersama untuk penanganan komorbid.')">+ Rawat Bersama</button>
                    <button type="button" class="tag-pill" onclick="appendUraianQuick('Setuju Alih Rawat ke DPJP Spesialis.')">+ Alih Rawat</button>
                    <button type="button" class="tag-pill" onclick="appendUraianQuick('Terapi dilanjutkan sesuai advice DPJP. Evaluasi berkala.')">+ Lanjutkan Terapi</button>
                    <button type="button" class="tag-pill" onclick="appendUraianQuick('Evaluasi post tindakan. Lapor ulang bila ada keluhan.')">+ Evaluasi Post Tindakan</button>
                </div>
            </div>

            <!-- Footer Action Buttons -->
            <div class="modal-action-footer">
                <button type="button" class="btn-cancel" onclick="tutupModalJawab()">Batal</button>
                <button type="submit" name="simpan_jawaban_medik" class="btn-submit">
                    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    <span id="mdl_btn_submit_text">Simpan Jawaban Medik</span>
                </button>
            </div>
        </form>
    </div>
</div>

<footer>
    &copy; <?php echo date('Y'); ?> IT <?php echo htmlspecialchars($nama_instansi); ?> &bull; Sistem Visite Dokter
</footer>

<script>
    let currentFilterStatus = 'all';
    let currentDiagnosaPemohon = '';

    function setViewMode(mode) {
        const cardContainer = document.getElementById('konsulCards');
        const tableContainer = document.getElementById('konsulTable');
        const btnCard = document.getElementById('btnCardView');
        const btnTable = document.getElementById('btnTableView');

        if (!cardContainer || !tableContainer) return;

        if (mode === 'card') {
            cardContainer.style.display = 'flex';
            tableContainer.style.display = 'none';
            btnCard.classList.add('active');
            btnTable.classList.remove('active');
        } else {
            cardContainer.style.display = 'none';
            tableContainer.style.display = 'block';
            btnCard.classList.remove('active');
            btnTable.classList.add('active');
        }
    }

    function filterByStatus(status) {
        currentFilterStatus = status;
        document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
        
        if (status === 'all') document.querySelector('.stat-total').classList.add('active');
        if (status === 'belum') document.querySelector('.stat-belum').classList.add('active');
        if (status === 'sudah') document.querySelector('.stat-sudah').classList.add('active');

        filterData();
    }

    function filterData() {
        const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
        const jenisFilter = (document.getElementById('selectJenisFilter').value || 'all').toLowerCase().trim();
        const cards = document.querySelectorAll('#konsulCards .konsul-card');
        const rows = document.querySelectorAll('#konsulTable tbody tr');

        function checkMatch(elem) {
            const elStatus = elem.getAttribute('data-status');
            const elJenis = (elem.getAttribute('data-jenis') || '').toLowerCase();
            const searchData = elem.getAttribute('data-search') || '';

            const statusMatch = (currentFilterStatus === 'all') || (elStatus === currentFilterStatus);
            const jenisMatch = (jenisFilter === 'all') || (elJenis === jenisFilter);
            const textMatch = !query || searchData.includes(query);

            return statusMatch && jenisMatch && textMatch;
        }

        cards.forEach(card => {
            card.style.display = checkMatch(card) ? 'block' : 'none';
        });

        rows.forEach(row => {
            row.style.display = checkMatch(row) ? '' : 'none';
        });
    }

    function updateCharCount(idInput, idCounter, max) {
        const el = document.getElementById(idInput);
        const counter = document.getElementById(idCounter);
        if (el && counter) {
            counter.textContent = el.value.length;
            if (el.value.length >= max) {
                counter.style.color = '#ef4444';
            } else {
                counter.style.color = 'var(--gray)';
            }
        }
    }

    function appendUraianQuick(text) {
        const area = document.getElementById('mdl_uraian_jawaban');
        if (!area) return;
        if (area.value.trim() === '') {
            area.value = text;
        } else {
            area.value = area.value + '\n' + text;
        }
        updateCharCount('mdl_uraian_jawaban', 'charCountUraian', 800);
        area.focus();
    }

    function setDatePreset(preset) {
        const today = new Date();
        const formatDate = (d) => {
            const year = d.getFullYear();
            const month = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            return `${year}-${month}-${day}`;
        };

        let start = new Date();
        let end = new Date();

        if (preset === 'hari_ini') {
            start = new Date();
            end = new Date();
        } else if (preset === '7_hari') {
            start.setDate(today.getDate() - 7);
            end = new Date();
        } else if (preset === '30_hari') {
            start.setDate(today.getDate() - 30);
            end = new Date();
        } else if (preset === 'bulan_ini') {
            start = new Date(today.getFullYear(), today.getMonth(), 1);
            end = new Date(today.getFullYear(), today.getMonth() + 1, 0);
        }

        document.getElementById('tglAwal').value = formatDate(start);
        document.getElementById('tglAkhir').value = formatDate(end);
        document.getElementById('dateFilterForm').submit();
    }

    function salinDiagnosaPemohon() {
        if (currentDiagnosaPemohon) {
            const input = document.getElementById('mdl_diagnosa_jawaban');
            input.value = currentDiagnosaPemohon;
            updateCharCount('mdl_diagnosa_jawaban', 'charCountDiag', 200);
        }
    }

    function formatTanggalIndo(dateStr) {
        if (!dateStr) return '-';
        const parts = dateStr.split(' ');
        if (parts.length === 2) {
            const d = parts[0].split('-');
            const t = parts[1].substring(0, 5);
            if (d.length === 3) {
                return `${d[2]}/${d[1]}/${d[0]} ${t}`;
            }
        }
        return dateStr;
    }

    // Modal Logic
    const modalJawab = document.getElementById('modalJawab');

    function bukaModalJawab(k) {
        document.getElementById('mdl_no_permintaan').value = k.no_permintaan || '';
        document.getElementById('mdl_nama_pasien').textContent = k.nm_pasien || '-';
        document.getElementById('mdl_no_rm').textContent = k.no_rkm_medis || '-';
        document.getElementById('mdl_no_rawat').textContent = k.no_rawat || '-';
        document.getElementById('mdl_lokasi').textContent = k.lokasi + (k.kd_kamar ? ' (' + k.kd_kamar + ')' : '');
        document.getElementById('mdl_dokter_pemohon').textContent = k.nm_dokter_pemohon || k.kd_dokter || '-';
        document.getElementById('mdl_jenis_permintaan').textContent = k.jenis_permintaan || '-';
        document.getElementById('mdl_tanggal').textContent = k.tgl_konsul ? formatTanggalIndo(k.tgl_konsul) : '-';

        // Detail Permintaan Pemohon
        currentDiagnosaPemohon = k.diagnosa_pemohon || '';
        document.getElementById('mdl_diagnosa_pemohon').textContent = k.diagnosa_pemohon || '-';
        document.getElementById('mdl_uraian_konsultasi').textContent = k.uraian_konsultasi || '-';

        // Jawaban Dokter dari tabel jawaban_konsultasi_medik
        const inputDiag = document.getElementById('mdl_diagnosa_jawaban');
        const inputUraian = document.getElementById('mdl_uraian_jawaban');

        inputDiag.value = k.diagnosa_jawaban || k.diagnosa_pemohon || '';
        inputUraian.value = k.uraian_jawaban || '';

        updateCharCount('mdl_diagnosa_jawaban', 'charCountDiag', 200);
        updateCharCount('mdl_uraian_jawaban', 'charCountUraian', 800);

        const infoAnswered = document.getElementById('mdl_last_answered_info');
        const btnSubmitText = document.getElementById('mdl_btn_submit_text');
        const modalTitle = document.getElementById('mdl_header_title');

        if (k.sudah_dijawab && k.tgl_jawaban) {
            infoAnswered.style.display = 'block';
            infoAnswered.innerHTML = '✅ <strong>Konsultasi Medik Ini Sudah Dijawab</strong> pada ' + formatTanggalIndo(k.tgl_jawaban) + '. Anda dapat memperbarui uraian jawaban di bawah ini.';
            btnSubmitText.textContent = 'Perbarui Jawaban Medik';
            modalTitle.textContent = '✏️ Ubah / Perbarui Jawaban Konsultasi Medik';
        } else {
            infoAnswered.style.display = 'none';
            infoAnswered.innerHTML = '';
            btnSubmitText.textContent = 'Simpan Jawaban Medik';
            modalTitle.textContent = '💬 Jawab Konsultasi Medik Antar Dokter';
        }

        modalJawab.style.display = 'block';
        document.body.style.overflow = 'hidden';

        setTimeout(() => {
            inputUraian.focus();
        }, 150);
    }

    function tutupModalJawab() {
        modalJawab.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    window.onclick = function(event) {
        if (event.target === modalJawab) {
            tutupModalJawab();
        }
    };

    // Auto-update clock
    setInterval(() => {
        const d = new Date();
        const h = String(d.getHours()).padStart(2, '0');
        const m = String(d.getMinutes()).padStart(2, '0');
        const el = document.getElementById('liveClock');
        if (el) el.textContent = `${h}:${m}`;
    }, 1000);
</script>

</body>
</html>
