<?php
require_once 'auth.php';

$pesan_sukses = '';
$pesan_error = '';

// Proses Simpan Data SOAPIE Baru (Copy / Input)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['simpan_soapie'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $pesan_error = "Token keamanan tidak valid. Silakan muat ulang halaman.";
    } else {
        $no_rawat    = mysqli_real_escape_string($koneksi, trim($_POST['no_rawat'] ?? ''));
        $suhu_tubuh  = mysqli_real_escape_string($koneksi, trim($_POST['suhu_tubuh'] ?? ''));
        $tensi       = mysqli_real_escape_string($koneksi, trim($_POST['tensi'] ?? ''));
        $nadi        = mysqli_real_escape_string($koneksi, trim($_POST['nadi'] ?? ''));
        $respirasi   = mysqli_real_escape_string($koneksi, trim($_POST['respirasi'] ?? ''));
        $tinggi      = mysqli_real_escape_string($koneksi, trim($_POST['tinggi'] ?? ''));
        $berat       = mysqli_real_escape_string($koneksi, trim($_POST['berat'] ?? ''));
        $spo2        = mysqli_real_escape_string($koneksi, trim($_POST['spo2'] ?? ''));
        $gcs         = mysqli_real_escape_string($koneksi, trim($_POST['gcs'] ?? ''));
        $kesadaran   = mysqli_real_escape_string($koneksi, trim($_POST['kesadaran'] ?? 'Compos Mentis'));
        $keluhan     = mysqli_real_escape_string($koneksi, trim($_POST['keluhan'] ?? ''));
        $pemeriksaan = mysqli_real_escape_string($koneksi, trim($_POST['pemeriksaan'] ?? ''));
        $alergi      = mysqli_real_escape_string($koneksi, trim($_POST['alergi'] ?? ''));
        $penilaian   = mysqli_real_escape_string($koneksi, trim($_POST['penilaian'] ?? ''));
        $rtl         = mysqli_real_escape_string($koneksi, trim($_POST['rtl'] ?? ''));
        $instruksi   = mysqli_real_escape_string($koneksi, trim($_POST['instruksi'] ?? ''));
        $evaluasi    = mysqli_real_escape_string($koneksi, trim($_POST['evaluasi'] ?? ''));

        // NIP petugas:
        // Jika super admin & ada kd_dokter DPJP pasien, gunakan kd_dokter tersebut atau username
        if ($is_super_admin && !empty($_POST['kd_dokter_dpjp'])) {
            $nip_simpan = mysqli_real_escape_string($koneksi, trim($_POST['kd_dokter_dpjp']));
        } else {
            $nip_simpan = !empty($kd_dokter) ? $kd_dokter : $username;
        }

        $tgl_perawatan = date('Y-m-d');
        $jam_rawat     = date('H:i:s');

        if (empty($no_rawat)) {
            $pesan_error = "No. Rawat tidak valid.";
        } else {
            $query_insert = "INSERT INTO pemeriksaan_ranap 
                (no_rawat, tgl_perawatan, jam_rawat, suhu_tubuh, tensi, nadi, respirasi, tinggi, berat, spo2, gcs, kesadaran, keluhan, pemeriksaan, alergi, penilaian, rtl, instruksi, evaluasi, nip) 
                VALUES 
                ('$no_rawat', '$tgl_perawatan', '$jam_rawat', '$suhu_tubuh', '$tensi', '$nadi', '$respirasi', '$tinggi', '$berat', '$spo2', '$gcs', '$kesadaran', '$keluhan', '$pemeriksaan', '$alergi', '$penilaian', '$rtl', '$instruksi', '$evaluasi', '$nip_simpan')";

            if (mysqli_query($koneksi, $query_insert)) {
                $pesan_sukses = "Data SOAPIE No. Rawat $no_rawat berhasil disimpan! Status pasien telah diperbarui menjadi 'Sudah Diperiksa'.";
            } else {
                $pesan_error = "Gagal menyimpan data SOAPIE: " . mysqli_error($koneksi);
            }
        }
    }
}

// Query untuk mengambil data pasien DPJP dengan status pemeriksaan hari ini
$tanggal_hari_ini = date('Y-m-d');
$data_pasien = array();

// Jika super admin, ambil semua data. Jika dokter biasa, hanya data mereka
if ($is_super_admin || $kd_dokter) {
    if ($is_super_admin) {
        $query_pasien = "SELECT DISTINCT
            dpjp_ranap.no_rawat,
            reg_periksa.no_rkm_medis,
            pasien.nm_pasien,
            penjab.png_jawab,
            dpjp_ranap.kd_dokter,
            dokter.nm_dokter,
            kamar_inap.diagnosa_awal,
            kamar.kd_kamar,
            bangsal.nm_bangsal,
            CASE 
                WHEN EXISTS (
                    SELECT 1 FROM pemeriksaan_ranap 
                    WHERE pemeriksaan_ranap.no_rawat = dpjp_ranap.no_rawat 
                    AND (
                        pemeriksaan_ranap.nip IN (
                            SELECT dokter.kd_dokter 
                            FROM dokter 
                            INNER JOIN dpjp_ranap d ON dokter.kd_dokter = d.kd_dokter 
                            WHERE d.no_rawat = dpjp_ranap.no_rawat
                        )
                        OR pemeriksaan_ranap.nip = ?
                    )
                    AND DATE(pemeriksaan_ranap.tgl_perawatan) = ?
                ) THEN 1 ELSE 0 
            END as sudah_periksa,
            CASE 
                WHEN DATE((
                    SELECT MIN(tgl_masuk) 
                    FROM kamar_inap ki2 
                    WHERE ki2.no_rawat = dpjp_ranap.no_rawat
                )) = CURDATE() THEN 1 ELSE 0 
            END as pasien_baru_hari_ini
        FROM dpjp_ranap
        INNER JOIN reg_periksa ON dpjp_ranap.no_rawat = reg_periksa.no_rawat
        INNER JOIN penjab ON reg_periksa.kd_pj = penjab.kd_pj
        INNER JOIN pasien ON reg_periksa.no_rkm_medis = pasien.no_rkm_medis
        INNER JOIN dokter ON dpjp_ranap.kd_dokter = dokter.kd_dokter
        INNER JOIN kamar_inap ON kamar_inap.no_rawat = reg_periksa.no_rawat
        INNER JOIN kamar ON kamar_inap.kd_kamar = kamar.kd_kamar
        INNER JOIN bangsal ON kamar.kd_bangsal = bangsal.kd_bangsal
        WHERE kamar_inap.stts_pulang = '-'
        ORDER BY dokter.nm_dokter, bangsal.nm_bangsal, kamar.kd_kamar";
    } else {
        $query_pasien = "SELECT DISTINCT
            dpjp_ranap.no_rawat,
            reg_periksa.no_rkm_medis,
            pasien.nm_pasien,
            penjab.png_jawab,
            dpjp_ranap.kd_dokter,
            kamar_inap.diagnosa_awal,
            kamar.kd_kamar,
            bangsal.nm_bangsal,
            CASE 
                WHEN EXISTS (
                    SELECT 1 FROM pemeriksaan_ranap 
                    WHERE pemeriksaan_ranap.no_rawat = dpjp_ranap.no_rawat 
                    AND (pemeriksaan_ranap.nip = ? OR pemeriksaan_ranap.nip = ?)
                    AND DATE(pemeriksaan_ranap.tgl_perawatan) = ?
                ) THEN 1 ELSE 0 
            END as sudah_periksa,
            CASE 
                WHEN DATE((
                    SELECT MIN(tgl_masuk) 
                    FROM kamar_inap ki2 
                    WHERE ki2.no_rawat = dpjp_ranap.no_rawat
                )) = CURDATE() THEN 1 ELSE 0 
            END as pasien_baru_hari_ini
        FROM dpjp_ranap
        INNER JOIN reg_periksa ON dpjp_ranap.no_rawat = reg_periksa.no_rawat
        INNER JOIN penjab ON reg_periksa.kd_pj = penjab.kd_pj
        INNER JOIN pasien ON reg_periksa.no_rkm_medis = pasien.no_rkm_medis
        INNER JOIN kamar_inap ON kamar_inap.no_rawat = reg_periksa.no_rawat
        INNER JOIN kamar ON kamar_inap.kd_kamar = kamar.kd_kamar
        INNER JOIN bangsal ON kamar.kd_bangsal = bangsal.kd_bangsal
        WHERE kamar_inap.stts_pulang = '-' 
        AND dpjp_ranap.kd_dokter = ?
        ORDER BY bangsal.nm_bangsal, kamar.kd_kamar";
    }
    
    $stmt_pasien = mysqli_prepare($koneksi, $query_pasien);
    if ($stmt_pasien) {
        if ($is_super_admin) {
            mysqli_stmt_bind_param($stmt_pasien, "ss", $username, $tanggal_hari_ini);
        } else {
            mysqli_stmt_bind_param($stmt_pasien, "ssss", $username, $kd_dokter, $tanggal_hari_ini, $kd_dokter);
        }
        mysqli_stmt_execute($stmt_pasien);
        $result_pasien = mysqli_stmt_get_result($stmt_pasien);
        while ($row = mysqli_fetch_assoc($result_pasien)) {
            $data_pasien[] = $row;
        }
        mysqli_stmt_close($stmt_pasien);
    }
}

// Hitung rekap status
$jumlah_belum_periksa = 0;
$jumlah_sudah_periksa = 0;
$jumlah_pasien_baru = 0;

foreach ($data_pasien as $pasien) {
    if ($pasien['pasien_baru_hari_ini']) {
        $jumlah_pasien_baru++;
    } else if ($pasien['sudah_periksa']) {
        $jumlah_sudah_periksa++;
    } else {
        $jumlah_belum_periksa++;
    }
}
$total_pasien = count($data_pasien);
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Rawat Inap - <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        :root {
            --primary: #0284c7;
            --primary-dark: #0369a1;
            --primary-light: #e0f2fe;
            --success: #16a34a;
            --success-dark: #15803d;
            --success-light: #dcfce7;
            --warning: #ea580c;
            --warning-light: #ffedd5;
            --info: #2563eb;
            --info-light: #dbeafe;
            --dark: #1e293b;
            --gray: #64748b;
            --light: #f8fafc;
            --card-border: #e2e8f0;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
            --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.05);
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
            background-color: #f1f5f9;
            color: var(--dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.5;
        }

        /* Top Header */
        .top-navbar {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: white;
            padding: 12px 16px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }

        .navbar-content {
            max-width: 1100px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .nav-left {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-back {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(255,255,255,0.2);
            color: white;
            text-decoration: none;
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: background 0.2s;
        }
        .btn-back:hover, .btn-back:active {
            background: rgba(255,255,255,0.35);
        }

        .header-title-box h1 {
            font-size: 17px;
            font-weight: 700;
            margin: 0;
            white-space: nowrap;
        }
        .header-title-box p {
            font-size: 11px;
            opacity: 0.9;
            margin: 0;
        }

        .main-container {
            max-width: 1100px;
            width: 100%;
            margin: 0 auto;
            padding: 16px;
            flex: 1;
        }

        /* Notification Alerts */
        .alert-box {
            padding: 14px 18px;
            border-radius: var(--radius);
            margin-bottom: 16px;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-sm);
        }
        .alert-success {
            background-color: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        .alert-danger {
            background-color: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }

        /* Info Banner */
        .meta-card {
            background: white;
            border-radius: var(--radius);
            padding: 14px 18px;
            margin-bottom: 16px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .meta-doctor {
            font-size: 14px;
        }
        .meta-doctor strong {
            color: var(--primary-dark);
            font-size: 15px;
        }

        .meta-date {
            font-size: 13px;
            color: var(--gray);
            background: #f8fafc;
            padding: 4px 10px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }

        .stat-card {
            background: white;
            border-radius: var(--radius);
            padding: 12px;
            text-align: center;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            cursor: pointer;
            transition: transform 0.15s, border-color 0.15s;
        }
        .stat-card:active {
            transform: scale(0.98);
        }
        .stat-card.active {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px var(--primary-light);
        }

        .stat-num {
            font-size: 22px;
            font-weight: 800;
            line-height: 1.1;
        }
        .stat-label {
            font-size: 11px;
            font-weight: 600;
            margin-top: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-total .stat-num { color: #0284c7; }
        .stat-total .stat-label { color: #0369a1; }

        .stat-belum .stat-num { color: #b45309; }
        .stat-belum .stat-label { color: #d97706; }

        .stat-sudah .stat-num { color: #15803d; }
        .stat-sudah .stat-label { color: #16a34a; }

        .stat-baru .stat-num { color: #1d4ed8; }
        .stat-baru .stat-label { color: #2563eb; }

        /* Search & Filter Toolbar */
        .toolbar {
            background: white;
            border-radius: var(--radius);
            padding: 12px;
            margin-bottom: 16px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }

        .search-box {
            flex: 1;
            min-width: 200px;
        }

        .search-input {
            width: 100%;
            padding: 10px 14px;
            border-radius: 8px;
            border: 1px solid #cbd5e1;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-input:focus {
            border-color: var(--primary);
        }

        .view-toggle {
            display: flex;
            background: #f1f5f9;
            padding: 3px;
            border-radius: 8px;
            gap: 2px;
        }
        .toggle-btn {
            border: none;
            background: transparent;
            padding: 6px 12px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            color: var(--gray);
        }
        .toggle-btn.active {
            background: white;
            color: var(--primary-dark);
            box-shadow: 0 1px 2px rgba(0,0,0,0.08);
        }

        /* Mobile Patient Cards */
        .patient-cards {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .patient-card {
            background: white;
            border-radius: var(--radius);
            padding: 16px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            position: relative;
            border-left: 5px solid #94a3b8;
        }

        .patient-card.status-sudah {
            border-left-color: #16a34a;
            background: linear-gradient(to right, #f0fdf4 0%, #ffffff 8%);
        }
        .patient-card.status-belum {
            border-left-color: #f59e0b;
            background: linear-gradient(to right, #fffbeb 0%, #ffffff 8%);
        }
        .patient-card.status-baru {
            border-left-color: #2563eb;
            background: linear-gradient(to right, #eff6ff 0%, #ffffff 8%);
        }

        .card-header-row {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 8px;
            margin-bottom: 8px;
        }

        .patient-name {
            font-size: 16px;
            font-weight: 700;
            color: #0f172a;
        }

        .status-badge {
            font-size: 11px;
            font-weight: 700;
            padding: 4px 8px;
            border-radius: 999px;
            white-space: nowrap;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        .badge-sudah { background: #dcfce7; color: #166534; }
        .badge-belum { background: #fef3c7; color: #92400e; }
        .badge-baru { background: #dbeafe; color: #1e40af; }

        .card-info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px 14px;
            font-size: 13px;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px dashed #e2e8f0;
        }

        .info-item {
            display: flex;
            flex-direction: column;
        }
        .info-label {
            font-size: 11px;
            color: var(--gray);
            margin-bottom: 2px;
        }
        .info-val {
            font-weight: 600;
            color: #334155;
            word-break: break-word;
        }

        /* SOAPIE Action Buttons */
        .card-action-bar {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #f1f5f9;
        }

        .btn-soapie-action {
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 10px 14px;
            border-radius: 8px;
            border: none;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        }
        .btn-soapie-action:active {
            transform: scale(0.98);
        }

        .btn-soapie-action.btn-action-belum {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: white;
        }
        .btn-soapie-action.btn-action-belum:hover {
            opacity: 0.95;
        }

        .btn-soapie-action.btn-action-sudah {
            background: #f0fdf4;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        .btn-soapie-action.btn-action-sudah:hover {
            background: #dcfce7;
        }

        /* Desktop Table View */
        .table-responsive {
            background: white;
            border-radius: var(--radius);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
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

        .row-sudah { background-color: #f0fdf4 !important; }
        .row-belum { background-color: #ffffff !important; }
        .row-baru  { background-color: #eff6ff !important; }

        .btn-table-soapie {
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
            transition: all 0.2s;
        }
        .btn-table-soapie.belum {
            background: var(--primary);
            color: white;
        }
        .btn-table-soapie.sudah {
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
            -webkit-backdrop-filter: blur(4px);
            padding: 12px;
        }

        .modal-content {
            background-color: #ffffff;
            margin: 20px auto;
            padding: 24px;
            width: 100%;
            max-width: 840px;
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
            transition: background 0.2s, color 0.2s;
        }
        .modal-close:hover {
            background: #fee2e2;
            color: #ef4444;
        }

        .modal-header-title {
            font-size: 18px;
            font-weight: 800;
            color: #0369a1;
            margin-bottom: 4px;
        }

        .patient-summary-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 12px 14px;
            margin: 12px 0 16px;
            font-size: 13px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px 20px;
            align-items: center;
        }
        .patient-summary-box strong {
            color: #0f172a;
        }

        .source-alert {
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }
        .source-alert.info {
            background-color: #eff6ff;
            color: #1e40af;
            border: 1px solid #bfdbfe;
        }
        .source-alert.empty {
            background-color: #fefce8;
            color: #854d0e;
            border: 1px solid #fef08a;
        }
        .source-alert.loading {
            background-color: #f1f5f9;
            color: #475569;
            border: 1px solid #cbd5e1;
        }

        .btn-reset-form {
            background: white;
            border: 1px solid #cbd5e1;
            color: #475569;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            white-space: nowrap;
        }
        .btn-reset-form:hover {
            background: #fee2e2;
            color: #dc2626;
            border-color: #fca5a5;
        }

        .section-label {
            font-size: 14px;
            font-weight: 700;
            color: #334155;
            padding-bottom: 6px;
            border-bottom: 2px solid #e2e8f0;
            margin: 18px 0 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .form-grid-ttv {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }

        .form-field {
            display: flex;
            flex-direction: column;
            margin-bottom: 12px;
        }
        .form-field label {
            font-size: 12px;
            font-weight: 600;
            color: #475569;
            margin-bottom: 4px;
        }
        .form-field input, .form-field select, .form-field textarea {
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid #cbd5e1;
            font-family: inherit;
            font-size: 13px;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
            background: white;
        }
        .form-field input:focus, .form-field select:focus, .form-field textarea:focus {
            border-color: #0284c7;
            box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15);
        }

        .form-field textarea {
            resize: vertical;
            min-height: 60px;
        }

        .modal-action-footer {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 24px;
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

        .btn-submit-soap {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: white;
            border: none;
            padding: 10px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(2, 132, 199, 0.3);
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .btn-submit-soap:hover {
            opacity: 0.95;
        }

        /* Empty State */
        .empty-box {
            background: white;
            border-radius: var(--radius);
            padding: 40px 20px;
            text-align: center;
            color: var(--gray);
            border: 1px dashed #cbd5e1;
        }
        .empty-box svg {
            width: 48px;
            height: 48px;
            stroke: #94a3b8;
            margin-bottom: 12px;
        }

        footer {
            text-align: center;
            padding: 18px;
            font-size: 12px;
            color: var(--gray);
            margin-top: auto;
        }

        @media (max-width: 640px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .form-grid-ttv {
                grid-template-columns: repeat(2, 1fr);
            }
            .main-container {
                padding: 12px;
            }
            .modal-content {
                padding: 18px 14px;
                margin: 10px auto;
            }
            .modal-action-footer {
                flex-direction: column-reverse;
                gap: 8px;
            }
            .modal-action-footer button {
                width: 100%;
                justify-content: center;
            }
        }

        @media (min-width: 860px) {
            .table-responsive.show-desktop {
                display: block;
            }
            .patient-cards.hide-desktop {
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
            <a href="index.php" class="btn-back" title="Kembali ke Beranda">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
                <span>Menu Utama</span>
            </a>
            <div class="header-title-box">
                <h1>Rawat Inap (Visite)</h1>
                <p><?php echo htmlspecialchars($nama_instansi); ?></p>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
            <a href="soapie_pasien.php" class="btn-back" style="background: rgba(255,255,255,0.15);" title="Buka Daftar Riwayat SOAPIE">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                <span>Riwayat</span>
            </a>
            <form method="POST" action="logout.php" style="margin:0;">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <button type="submit" class="btn-back" style="border:none; cursor:pointer; background: rgba(220, 53, 69, 0.4);" onclick="return confirm('Apakah Anda yakin ingin logout?');">
                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
                    <span>Logout</span>
                </button>
            </form>
        </div>
    </div>
</header>

<main class="main-container">
    <!-- Feedback Alert Messages -->
    <?php if (!empty($pesan_sukses)): ?>
        <div class="alert-box alert-success">
            <span>✅ <?php echo $pesan_sukses; ?></span>
            <button type="button" onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;font-size:16px;cursor:pointer;">&times;</button>
        </div>
    <?php endif; ?>

    <?php if (!empty($pesan_error)): ?>
        <div class="alert-box alert-danger">
            <span>❌ <?php echo $pesan_error; ?></span>
            <button type="button" onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;font-size:16px;cursor:pointer;">&times;</button>
        </div>
    <?php endif; ?>

    <!-- Meta Info Card -->
    <div class="meta-card">
        <div class="meta-doctor">
            DPJP: <strong><?php echo htmlspecialchars($nama_pegawai); ?></strong>
            <?php if ($is_super_admin): ?>
                <span style="background: #fee2e2; color: #dc2626; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; margin-left: 6px;">SUPER ADMIN</span>
            <?php elseif ($kd_dokter): ?>
                <span style="color: var(--gray); font-size: 12px; margin-left: 6px;">(<?php echo htmlspecialchars($kd_dokter); ?>)</span>
            <?php endif; ?>
        </div>
        <div class="meta-date">
            📅 <?php echo date('d/m/Y'); ?> | ⏰ <span id="liveClock"><?php echo date('H:i'); ?></span> WIB
        </div>
    </div>

    <!-- Stats Summary -->
    <div class="stats-grid">
        <div class="stat-card stat-total active" onclick="filterByStatus('all')">
            <div class="stat-num"><?php echo $total_pasien; ?></div>
            <div class="stat-label">Total Pasien</div>
        </div>
        <div class="stat-card stat-belum" onclick="filterByStatus('belum')">
            <div class="stat-num"><?php echo $jumlah_belum_periksa; ?></div>
            <div class="stat-label">Belum Diperiksa</div>
        </div>
        <div class="stat-card stat-sudah" onclick="filterByStatus('sudah')">
            <div class="stat-num"><?php echo $jumlah_sudah_periksa; ?></div>
            <div class="stat-label">Sudah Diperiksa</div>
        </div>
        <div class="stat-card stat-baru" onclick="filterByStatus('baru')">
            <div class="stat-num"><?php echo $jumlah_pasien_baru; ?></div>
            <div class="stat-label">Pasien Baru</div>
        </div>
    </div>

    <!-- Search & Filter Bar -->
    <div class="toolbar">
        <div class="search-box">
            <input type="text" id="searchInput" class="search-input" placeholder="🔍 Cari nama pasien, No RM, bangsal, kamar..." onkeyup="filterPatients()">
        </div>
        <div class="view-toggle">
            <button type="button" class="toggle-btn active" id="btnCardView" onclick="setViewMode('card')">📱 Kartu</button>
            <button type="button" class="toggle-btn" id="btnTableView" onclick="setViewMode('table')">📋 Tabel</button>
        </div>
    </div>

    <?php if (count($data_pasien) > 0): ?>
        <!-- Mobile/Card View (Default on phone) -->
        <div class="patient-cards hide-desktop" id="patientCards">
            <?php 
            $no = 1;
            foreach ($data_pasien as $pasien): 
                if ($pasien['pasien_baru_hari_ini']) {
                    $status_key = 'baru';
                    $status_text = 'Pasien Baru';
                    $badge_class = 'badge-baru';
                    $card_class = 'status-baru';
                } else if ($pasien['sudah_periksa']) {
                    $status_key = 'sudah';
                    $status_text = 'Sudah Periksa';
                    $badge_class = 'badge-sudah';
                    $card_class = 'status-sudah';
                } else {
                    $status_key = 'belum';
                    $status_text = 'Belum Periksa';
                    $badge_class = 'badge-belum';
                    $card_class = 'status-belum';
                }

                $json_patient = htmlspecialchars(json_encode([
                    'no_rawat'      => $pasien['no_rawat'],
                    'no_rkm_medis'  => $pasien['no_rkm_medis'],
                    'nm_pasien'     => $pasien['nm_pasien'],
                    'nm_bangsal'    => $pasien['nm_bangsal'],
                    'kd_kamar'      => $pasien['kd_kamar'],
                    'kd_dokter'     => $pasien['kd_dokter'] ?? ''
                ]), ENT_QUOTES, 'UTF-8');
            ?>
                <div class="patient-card <?php echo $card_class; ?>" data-status="<?php echo $status_key; ?>" data-search="<?php echo strtolower($pasien['nm_pasien'] . ' ' . $pasien['no_rkm_medis'] . ' ' . $pasien['no_rawat'] . ' ' . $pasien['nm_bangsal'] . ' ' . $pasien['kd_kamar'] . ' ' . $pasien['diagnosa_awal']); ?>">
                    <div class="card-header-row">
                        <div>
                            <div style="font-size: 11px; color: var(--gray); font-weight: 600;">#<?php echo $no++; ?> &bull; No. Rawat: <?php echo htmlspecialchars($pasien['no_rawat']); ?></div>
                            <div class="patient-name"><?php echo htmlspecialchars($pasien['nm_pasien']); ?></div>
                        </div>
                        <span class="status-badge <?php echo $badge_class; ?>"><?php echo $status_text; ?></span>
                    </div>

                    <div class="card-info-grid">
                        <div class="info-item">
                            <span class="info-label">No. Rekam Medis</span>
                            <span class="info-val"><?php echo htmlspecialchars($pasien['no_rkm_medis']); ?></span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Penjamin</span>
                            <span class="info-val"><?php echo htmlspecialchars($pasien['png_jawab']); ?></span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Bangsal & Kamar</span>
                            <span class="info-val">🏥 <?php echo htmlspecialchars($pasien['nm_bangsal']); ?> (<?php echo htmlspecialchars($pasien['kd_kamar']); ?>)</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Diagnosa Awal</span>
                            <span class="info-val"><?php echo !empty($pasien['diagnosa_awal']) ? htmlspecialchars($pasien['diagnosa_awal']) : '-'; ?></span>
                        </div>
                        <?php if ($is_super_admin): ?>
                        <div class="info-item" style="grid-column: 1 / -1;">
                            <span class="info-label">Dokter DPJP</span>
                            <span class="info-val">👨‍⚕️ <?php echo htmlspecialchars($pasien['nm_dokter']); ?></span>
                        </div>
                        <?php endif; ?>
                    </div>

                    <!-- Tombol Isi / Copy SOAPIE Mobile -->
                    <div class="card-action-bar">
                        <?php if ($pasien['sudah_periksa']): ?>
                            <button type="button" class="btn-soapie-action btn-action-sudah" onclick='bukaModalSoapie(<?php echo $json_patient; ?>)'>
                                <span>✏️ Edit / Tambah SOAPIE</span>
                            </button>
                        <?php else: ?>
                            <button type="button" class="btn-soapie-action btn-action-belum" onclick='bukaModalSoapie(<?php echo $json_patient; ?>)'>
                                <span>📝 Isi / Copy SOAPIE</span>
                            </button>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Table View (Desktop & Toggleable) -->
        <div class="table-responsive show-desktop" id="patientTable">
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px;">No</th>
                        <th>No. Rawat</th>
                        <th>No. RM</th>
                        <th>Nama Pasien</th>
                        <th>Penjamin</th>
                        <?php if ($is_super_admin): ?>
                            <th>Dokter DPJP</th>
                        <?php endif; ?>
                        <th>Bangsal / Kamar</th>
                        <th>Diagnosa Awal</th>
                        <th>Status</th>
                        <th style="text-align:center; width: 140px;">Aksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $no = 1;
                    foreach ($data_pasien as $pasien): 
                        if ($pasien['pasien_baru_hari_ini']) {
                            $status_key = 'baru';
                            $row_class = 'row-baru';
                            $badge = '<span class="status-badge badge-baru">Pasien Baru</span>';
                        } else if ($pasien['sudah_periksa']) {
                            $status_key = 'sudah';
                            $row_class = 'row-sudah';
                            $badge = '<span class="status-badge badge-sudah">Sudah Periksa</span>';
                        } else {
                            $status_key = 'belum';
                            $row_class = 'row-belum';
                            $badge = '<span class="status-badge badge-belum">Belum Periksa</span>';
                        }

                        $json_patient = htmlspecialchars(json_encode([
                            'no_rawat'      => $pasien['no_rawat'],
                            'no_rkm_medis'  => $pasien['no_rkm_medis'],
                            'nm_pasien'     => $pasien['nm_pasien'],
                            'nm_bangsal'    => $pasien['nm_bangsal'],
                            'kd_kamar'      => $pasien['kd_kamar'],
                            'kd_dokter'     => $pasien['kd_dokter'] ?? ''
                        ]), ENT_QUOTES, 'UTF-8');
                    ?>
                        <tr class="<?php echo $row_class; ?>" data-status="<?php echo $status_key; ?>" data-search="<?php echo strtolower($pasien['nm_pasien'] . ' ' . $pasien['no_rkm_medis'] . ' ' . $pasien['no_rawat'] . ' ' . $pasien['nm_bangsal'] . ' ' . $pasien['kd_kamar'] . ' ' . $pasien['diagnosa_awal']); ?>">
                            <td><?php echo $no++; ?></td>
                            <td><strong><?php echo htmlspecialchars($pasien['no_rawat']); ?></strong></td>
                            <td><?php echo htmlspecialchars($pasien['no_rkm_medis']); ?></td>
                            <td><strong><?php echo htmlspecialchars($pasien['nm_pasien']); ?></strong></td>
                            <td><?php echo htmlspecialchars($pasien['png_jawab']); ?></td>
                            <?php if ($is_super_admin): ?>
                                <td><?php echo htmlspecialchars($pasien['nm_dokter']); ?></td>
                            <?php endif; ?>
                            <td><?php echo htmlspecialchars($pasien['nm_bangsal']); ?> <small style="color:var(--gray);">(<?php echo htmlspecialchars($pasien['kd_kamar']); ?>)</small></td>
                            <td><?php echo !empty($pasien['diagnosa_awal']) ? htmlspecialchars($pasien['diagnosa_awal']) : '-'; ?></td>
                            <td><?php echo $badge; ?></td>
                            <td style="text-align:center;">
                                <?php if ($pasien['sudah_periksa']): ?>
                                    <button type="button" class="btn-table-soapie sudah" onclick='bukaModalSoapie(<?php echo $json_patient; ?>)'>
                                        ✏️ Edit SOAPIE
                                    </button>
                                <?php else: ?>
                                    <button type="button" class="btn-table-soapie belum" onclick='bukaModalSoapie(<?php echo $json_patient; ?>)'>
                                        📝 Isi SOAPIE
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <div class="empty-box">
            <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>
            <h3 style="font-size: 16px; margin-bottom: 6px; color: #334155;">Tidak Ada Pasien Aktif</h3>
            <p style="font-size: 13px;">Tidak ditemukan data pasien rawat inap yang menjadi tanggung jawab Anda saat ini.</p>
        </div>
    <?php endif; ?>
</main>

<!-- Modal Input / Copy SOAPIE -->
<div id="modalSoapie" class="modal">
    <div class="modal-content">
        <button type="button" class="modal-close" onclick="tutupModalSoapie()">&times;</button>
        
        <h3 class="modal-header-title">Pemeriksaan SOAPIE Pasien</h3>
        <p style="font-size: 12px; color: var(--gray); margin-bottom: 8px;">Salin data terakhir atau input pemeriksaan baru untuk visite hari ini</p>

        <!-- Ringkasan Pasien -->
        <div class="patient-summary-box">
            <div>Pasien: <strong id="mdl_nama_pasien">-</strong></div>
            <div>No. RM: <strong id="mdl_no_rm">-</strong></div>
            <div>No. Rawat: <strong id="mdl_no_rawat_disp" style="font-family:monospace;">-</strong></div>
            <div>Kamar: <strong id="mdl_kamar_bangsal">-</strong></div>
        </div>

        <!-- Alert Status Copy / Fetching -->
        <div id="mdl_source_alert" class="source-alert loading">
            <span id="mdl_source_text">⏳ Sedang memeriksa data SOAPIE sebelumnya...</span>
            <button type="button" id="btn_clear_form" class="btn-reset-form" onclick="resetFormKosong()" style="display:none;">🔄 Kosongkan Form</button>
        </div>

        <form method="POST" action="" id="formSoapie">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="no_rawat" id="mdl_no_rawat">
            <input type="hidden" name="kd_dokter_dpjp" id="mdl_kd_dokter_dpjp">

            <!-- Tanda-Tanda Vital (TTV) -->
            <div class="section-label">
                <span>🩺</span> Tanda-Tanda Vital & Kondisi Fisik
            </div>

            <div class="form-grid-ttv">
                <div class="form-field">
                    <label>Suhu Tubuh (°C)</label>
                    <input type="text" name="suhu_tubuh" id="mdl_suhu_tubuh" placeholder="Misal: 36.5">
                </div>
                <div class="form-field">
                    <label>Tensi (mmHg)</label>
                    <input type="text" name="tensi" id="mdl_tensi" placeholder="Misal: 120/80">
                </div>
                <div class="form-field">
                    <label>Nadi (x/menit)</label>
                    <input type="text" name="nadi" id="mdl_nadi" placeholder="Misal: 80">
                </div>
                <div class="form-field">
                    <label>Respirasi (x/menit)</label>
                    <input type="text" name="respirasi" id="mdl_respirasi" placeholder="Misal: 20">
                </div>
                <div class="form-field">
                    <label>Tinggi Badan (cm)</label>
                    <input type="text" name="tinggi" id="mdl_tinggi" placeholder="cm">
                </div>
                <div class="form-field">
                    <label>Berat Badan (kg)</label>
                    <input type="text" name="berat" id="mdl_berat" placeholder="kg">
                </div>
                <div class="form-field">
                    <label>SpO2 (%)</label>
                    <input type="text" name="spo2" id="mdl_spo2" placeholder="Misal: 98">
                </div>
                <div class="form-field">
                    <label>GCS</label>
                    <input type="text" name="gcs" id="mdl_gcs" placeholder="Misal: 15 / E4V5M6">
                </div>
                <div class="form-field" style="grid-column: 1 / -1;">
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px;">
                        <div>
                            <label>Tingkat Kesadaran</label>
                            <select name="kesadaran" id="mdl_kesadaran">
                                <option value="Compos Mentis">Compos Mentis</option>
                                <option value="Somnolence">Somnolence</option>
                                <option value="Sopor">Sopor</option>
                                <option value="Coma">Coma</option>
                                <option value="Alert">Alert</option>
                                <option value="Confusion">Confusion</option>
                                <option value="Voice">Voice</option>
                                <option value="Pain">Pain</option>
                                <option value="Unresponsive">Unresponsive</option>
                                <option value="Apatis">Apatis</option>
                                <option value="Delirium">Delirium</option>
                                <option value="Meninggal">Meninggal</option>
                            </select>
                        </div>
                        <div>
                            <label>Riwayat Alergi</label>
                            <input type="text" name="alergi" id="mdl_alergi" placeholder="Tidak ada alergi">
                        </div>
                    </div>
                </div>
            </div>

            <!-- Catatan SOAPIE -->
            <div class="section-label">
                <span>📝</span> Catatan Klinis SOAPIE
            </div>

            <div class="form-field">
                <label>Subjektif / Keluhan (S) <span style="color:#ef4444;">*</span></label>
                <textarea name="keluhan" id="mdl_keluhan" rows="2" placeholder="Keluhan utama dan riwayat penyakit saat ini..." required></textarea>
            </div>

            <div class="form-field">
                <label>Objektif / Pemeriksaan Fisik (O)</label>
                <textarea name="pemeriksaan" id="mdl_pemeriksaan" rows="2" placeholder="Hasil pemeriksaan fisik, laboratorium, radiologi..."></textarea>
            </div>

            <div class="form-field">
                <label>Assessment / Penilaian Klinis (A)</label>
                <textarea name="penilaian" id="mdl_penilaian" rows="2" placeholder="Diagnosa kerja, evaluasi klinis..."></textarea>
            </div>

            <div class="form-field">
                <label>Plan / Instruksi Medis (P)</label>
                <textarea name="instruksi" id="mdl_instruksi" rows="2" placeholder="Terapi obat, instruksi dokter, rencana tindakan..."></textarea>
            </div>

            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div class="form-field">
                    <label>Rencana Tindak Lanjut (RTL)</label>
                    <textarea name="rtl" id="mdl_rtl" rows="2" placeholder="RTL / rencana kontrol..."></textarea>
                </div>
                <div class="form-field">
                    <label>Evaluasi</label>
                    <textarea name="evaluasi" id="mdl_evaluasi" rows="2" placeholder="Evaluasi kondisi pasien..."></textarea>
                </div>
            </div>

            <!-- Footer Action Buttons -->
            <div class="modal-action-footer">
                <button type="button" class="btn-cancel" onclick="tutupModalSoapie()">Batal</button>
                <button type="submit" name="simpan_soapie" class="btn-submit-soap">
                    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    <span>Simpan Pemeriksaan</span>
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

    function setViewMode(mode) {
        const cardContainer = document.getElementById('patientCards');
        const tableContainer = document.getElementById('patientTable');
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
        if (status === 'baru') document.querySelector('.stat-baru').classList.add('active');

        filterPatients();
    }

    function filterPatients() {
        const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
        
        const cards = document.querySelectorAll('#patientCards .patient-card');
        const rows = document.querySelectorAll('#patientTable tbody tr');

        function checkMatch(elem) {
            const elStatus = elem.getAttribute('data-status');
            const searchData = elem.getAttribute('data-search') || '';

            const statusMatch = (currentFilterStatus === 'all') || (elStatus === currentFilterStatus);
            const textMatch = !query || searchData.includes(query);

            return statusMatch && textMatch;
        }

        cards.forEach(card => {
            card.style.display = checkMatch(card) ? 'block' : 'none';
        });

        rows.forEach(row => {
            row.style.display = checkMatch(row) ? '' : 'none';
        });
    }

    // Modal SOAPIE Logic
    const modalSoapie = document.getElementById('modalSoapie');

    function bukaModalSoapie(patient) {
        // Set Header info
        document.getElementById('mdl_nama_pasien').textContent = patient.nm_pasien || '-';
        document.getElementById('mdl_no_rm').textContent = patient.no_rkm_medis || '-';
        document.getElementById('mdl_no_rawat_disp').textContent = patient.no_rawat || '-';
        document.getElementById('mdl_no_rawat').value = patient.no_rawat || '';
        document.getElementById('mdl_kd_dokter_dpjp').value = patient.kd_dokter || '';

        const kamarBangsal = (patient.nm_bangsal || '-') + (patient.kd_kamar ? ' (' + patient.kd_kamar + ')' : '');
        document.getElementById('mdl_kamar_bangsal').textContent = kamarBangsal;

        // Reset form to blank initially
        resetFormKosong();

        // Update alert to loading
        const alertBox = document.getElementById('mdl_source_alert');
        const alertText = document.getElementById('mdl_source_text');
        const btnClear = document.getElementById('btn_clear_form');

        alertBox.className = 'source-alert loading';
        alertText.innerHTML = '⏳ Mengambil data SOAPIE terakhir...';
        btnClear.style.display = 'none';

        modalSoapie.style.display = 'block';
        document.body.style.overflow = 'hidden';

        // Fetch data SOAPIE terakhir via AJAX
        fetch('get_soapie.php?no_rawat=' + encodeURIComponent(patient.no_rawat))
            .then(res => res.json())
            .then(res => {
                if (res.status === 'success' && res.found && res.data) {
                    const d = res.data;
                    document.getElementById('mdl_suhu_tubuh').value = d.suhu_tubuh || '';
                    document.getElementById('mdl_tensi').value = d.tensi || '';
                    document.getElementById('mdl_nadi').value = d.nadi || '';
                    document.getElementById('mdl_respirasi').value = d.respirasi || '';
                    document.getElementById('mdl_tinggi').value = d.tinggi || '';
                    document.getElementById('mdl_berat').value = d.berat || '';
                    document.getElementById('mdl_spo2').value = d.spo2 || '';
                    document.getElementById('mdl_gcs').value = d.gcs || '';
                    if (d.kesadaran) document.getElementById('mdl_kesadaran').value = d.kesadaran;
                    document.getElementById('mdl_alergi').value = d.alergi || '';

                    document.getElementById('mdl_keluhan').value = d.keluhan || '';
                    document.getElementById('mdl_pemeriksaan').value = d.pemeriksaan || '';
                    document.getElementById('mdl_penilaian').value = d.penilaian || '';
                    document.getElementById('mdl_instruksi').value = d.instruksi || '';
                    document.getElementById('mdl_rtl').value = d.rtl || '';
                    document.getElementById('mdl_evaluasi').value = d.evaluasi || '';

                    alertBox.className = 'source-alert info';
                    alertText.innerHTML = '📋 <strong>Data disalin</strong> dari pemeriksaan: ' + (d.tgl_perawatan || '') + ' ' + (d.jam_rawat || '') + ' (' + (d.nama_petugas || d.nip || 'Petugas') + '). Silakan sesuaikan.';
                    btnClear.style.display = 'inline-block';
                } else {
                    alertBox.className = 'source-alert empty';
                    alertText.innerHTML = 'ℹ️ Belum ada riwayat SOAPIE untuk rawat ini. Silakan input pemeriksaan baru.';
                    btnClear.style.display = 'none';
                }
            })
            .catch(err => {
                console.error(err);
                alertBox.className = 'source-alert empty';
                alertText.innerHTML = 'ℹ️ Masukkan data pemeriksaan baru.';
                btnClear.style.display = 'none';
            });
    }

    function resetFormKosong() {
        document.getElementById('mdl_suhu_tubuh').value = '';
        document.getElementById('mdl_tensi').value = '';
        document.getElementById('mdl_nadi').value = '';
        document.getElementById('mdl_respirasi').value = '';
        document.getElementById('mdl_tinggi').value = '';
        document.getElementById('mdl_berat').value = '';
        document.getElementById('mdl_spo2').value = '';
        document.getElementById('mdl_gcs').value = '';
        document.getElementById('mdl_kesadaran').value = 'Compos Mentis';
        document.getElementById('mdl_alergi').value = '';
        document.getElementById('mdl_keluhan').value = '';
        document.getElementById('mdl_pemeriksaan').value = '';
        document.getElementById('mdl_penilaian').value = '';
        document.getElementById('mdl_instruksi').value = '';
        document.getElementById('mdl_rtl').value = '';
        document.getElementById('mdl_evaluasi').value = '';
    }

    function tutupModalSoapie() {
        modalSoapie.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    window.onclick = function(event) {
        if (event.target === modalSoapie) {
            tutupModalSoapie();
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
