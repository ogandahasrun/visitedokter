<?php
require_once 'auth.php';

$pesan_sukses = '';
$pesan_error = '';

// Proses Simpan / Update Jawaban Konsultasi Perawat
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['simpan_konsultasi'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $pesan_error = "Token keamanan tidak valid. Silakan muat ulang halaman.";
    } else {
        $post_no_permintaan  = mysqli_real_escape_string($koneksi, trim($_POST['no_permintaan'] ?? ''));
        $post_situation      = mysqli_real_escape_string($koneksi, trim($_POST['situation'] ?? ''));
        $post_background     = mysqli_real_escape_string($koneksi, trim($_POST['background'] ?? ''));
        $post_assessment     = mysqli_real_escape_string($koneksi, trim($_POST['assessment'] ?? ''));
        $post_recomendation  = mysqli_real_escape_string($koneksi, trim($_POST['recomendation'] ?? ''));

        if (empty($post_no_permintaan)) {
            $pesan_error = "No. Permintaan konsultasi tidak valid.";
        } else {
            // Pastikan verifikasi hak akses: jika bukan super admin, pastikan milik dokter ini
            $where_hak = "";
            if (!$is_super_admin && !empty($kd_dokter)) {
                $where_hak = " AND kd_dokter_dikonsuli = '" . mysqli_real_escape_string($koneksi, $kd_dokter) . "'";
            }

            $query_update = "UPDATE konsultasi_perawat 
                             SET situation = '$post_situation',
                                 background = '$post_background',
                                 assessment = '$post_assessment',
                                 recomendation = '$post_recomendation'
                             WHERE no_permintaan = '$post_no_permintaan' $where_hak";

            if (mysqli_query($koneksi, $query_update)) {
                $pesan_sukses = "Konsultasi No. $post_no_permintaan berhasil disimpan & diperbarui!";
            } else {
                $pesan_error = "Gagal memperbarui konsultasi: " . mysqli_error($koneksi);
            }
        }
    }
}

// Filter Status Jawab & Pencarian
$filter_status = isset($_GET['status']) ? trim($_GET['status']) : 'all'; // all, belum, sudah
$keyword = isset($_GET['keyword']) ? trim($_GET['keyword']) : '';

// Query Konsultasi Perawat sesuai Hak Akses Akun Login
$data_konsul = array();

$sql = "SELECT kp.no_permintaan, kp.no_rawat, kp.tanggal, kp.nip, kp.kd_dokter_dikonsuli,
               kp.situation, kp.background, kp.assessment, kp.recomendation,
               p.nm_pasien, rp.no_rkm_medis, pj.png_jawab,
               peg.nama as nm_perawat, dok.nm_dokter,
               COALESCE(ki.diagnosa_awal, '-') as diagnosa_awal,
               COALESCE(b.nm_bangsal, poli.nm_poli, '-') as lokasi,
               COALESCE(k.kd_kamar, '') as kd_kamar,
               CASE 
                   WHEN (kp.recomendation IS NOT NULL 
                         AND TRIM(kp.recomendation) != '' 
                         AND TRIM(kp.recomendation) != '-') THEN 1 
                   ELSE 0 
               END as sudah_dijawab
        FROM konsultasi_perawat kp
        INNER JOIN reg_periksa rp ON kp.no_rawat = rp.no_rawat
        INNER JOIN pasien p ON rp.no_rkm_medis = p.no_rkm_medis
        LEFT JOIN penjab pj ON rp.kd_pj = pj.kd_pj
        LEFT JOIN pegawai peg ON kp.nip = peg.nik
        LEFT JOIN dokter dok ON kp.kd_dokter_dikonsuli = dok.kd_dokter
        LEFT JOIN kamar_inap ki ON kp.no_rawat = ki.no_rawat AND ki.stts_pulang = '-'
        LEFT JOIN kamar k ON ki.kd_kamar = k.kd_kamar
        LEFT JOIN bangsal b ON k.kd_bangsal = b.kd_bangsal
        LEFT JOIN poliklinik poli ON rp.kd_poli = poli.kd_poli";

if ($is_super_admin) {
    $sql .= " WHERE 1=1";
} else {
    // Dokter yang sedang login
    $sql .= " WHERE kp.kd_dokter_dikonsuli = '" . mysqli_real_escape_string($koneksi, $kd_dokter) . "'";
}

$sql .= " ORDER BY kp.tanggal DESC LIMIT 200";

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
    <title>Konsultasi Perawat - <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        :root {
            --primary: #f59e0b;
            --primary-dark: #d97706;
            --primary-light: #fef3c7;
            --primary-teal: #0d9488;
            --success: #16a34a;
            --warning: #ea580c;
            --info: #0284c7;
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
            background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
            color: white;
            padding: 12px 16px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
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
            background: #fffbeb;
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

        .stat-total .stat-val { color: #d97706; }
        .stat-belum .stat-val { color: #dc2626; }
        .stat-sudah .stat-val { color: #16a34a; }

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
            border-color: #d97706;
            box-shadow: 0 0 0 3px rgba(217, 119, 6, 0.15);
        }
        .search-box svg {
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: #94a3b8;
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
            color: #d97706;
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
            color: #d97706;
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

        /* SBAR Preview Box */
        .sbar-preview-box {
            background: #f8fafc;
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 12px;
            font-size: 12px;
            line-height: 1.5;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .sbar-preview-item {
            display: flex;
            gap: 6px;
        }
        .sbar-tag {
            font-weight: 800;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 10px;
            flex-shrink: 0;
            height: fit-content;
        }
        .sbar-tag.s { background: #e0f2fe; color: #0369a1; }
        .sbar-tag.b { background: #fef3c7; color: #92400e; }
        .sbar-tag.a { background: #fce7f3; color: #9d174d; }
        .sbar-tag.r { background: #dcfce7; color: #166534; }

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
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            box-shadow: 0 2px 4px rgba(245, 158, 11, 0.3);
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
            background: #d97706;
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
            max-width: 800px;
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
            color: #d97706;
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

        .section-label {
            font-size: 14px;
            font-weight: 700;
            color: #334155;
            padding-bottom: 6px;
            border-bottom: 2px solid #fde68a;
            margin: 16px 0 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .form-field {
            display: flex;
            flex-direction: column;
            margin-bottom: 12px;
        }
        .form-field label {
            font-size: 12px;
            font-weight: 700;
            color: #475569;
            margin-bottom: 4px;
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
            border-color: #d97706;
            box-shadow: 0 0 0 3px rgba(217, 119, 6, 0.15);
        }
        .form-field textarea {
            resize: vertical;
            min-height: 65px;
        }

        .recom-highlight {
            border-left: 4px solid #16a34a;
            padding-left: 8px;
            margin-top: 6px;
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
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            border: none;
            padding: 10px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(217, 119, 6, 0.3);
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
                <h1>Konsultasi Perawat (SBAR)</h1>
                <p><?php echo htmlspecialchars($nama_pegawai); ?> <?php echo $is_super_admin ? '(Super Admin)' : '(Dokter DPJP)'; ?></p>
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

    <!-- Filter & Search Toolbar -->
    <div class="filter-section">
        <div class="search-box">
            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
            <input type="text" id="searchInput" placeholder="Cari nama pasien, no rawat, kamar, perawat, atau situasi..." oninput="filterData()">
        </div>
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

    <?php if (!empty($data_konsul)): ?>
        <!-- Mobile Card List -->
        <div class="cards-container hide-desktop" id="konsulCards">
            <?php foreach ($data_konsul as $k): 
                $status_key = $k['sudah_dijawab'] ? 'sudah' : 'belum';
                $badge_class = $k['sudah_dijawab'] ? 'badge-sudah' : 'badge-belum';
                $status_text = $k['sudah_dijawab'] ? 'Sudah Dijawab' : 'Belum Dijawab';
                $json_konsul = htmlspecialchars(json_encode($k), ENT_QUOTES, 'UTF-8');
            ?>
                <div class="konsul-card" data-status="<?php echo $status_key; ?>" data-search="<?php echo strtolower($k['nm_pasien'] . ' ' . $k['no_rkm_medis'] . ' ' . $k['no_rawat'] . ' ' . $k['no_permintaan'] . ' ' . $k['lokasi'] . ' ' . $k['nm_perawat'] . ' ' . $k['situation']); ?>">
                    <div class="card-header-row">
                        <div class="card-title-group">
                            <div class="card-no-permintaan">#<?php echo htmlspecialchars($k['no_permintaan']); ?> &bull; <?php echo date('d/m/Y H:i', strtotime($k['tanggal'])); ?></div>
                            <div class="card-patient-name"><?php echo htmlspecialchars($k['nm_pasien']); ?></div>
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
                            <span class="info-cell-label">Perawat Pengirim</span>
                            <span class="info-cell-val">👩‍⚕️ <?php echo htmlspecialchars($k['nm_perawat'] ?? $k['nip']); ?></span>
                        </div>
                        <div class="info-cell">
                            <span class="info-cell-label">Diagnosa Awal</span>
                            <span class="info-cell-val"><?php echo htmlspecialchars($k['diagnosa_awal']); ?></span>
                        </div>
                    </div>

                    <!-- Ringkasan SBAR Singkat -->
                    <div class="sbar-preview-box">
                        <div class="sbar-preview-item">
                            <span class="sbar-tag s">S</span>
                            <span><?php echo htmlspecialchars(mb_strimwidth($k['situation'] ?? '-', 0, 100, '...')); ?></span>
                        </div>
                        <div class="sbar-preview-item">
                            <span class="sbar-tag r">R</span>
                            <span style="font-weight:600; color:#15803d;"><?php echo !empty($k['recomendation']) ? htmlspecialchars(mb_strimwidth($k['recomendation'], 0, 100, '...')) : '<em>(Belum ada rekomendasi/instruksi dokter)</em>'; ?></span>
                        </div>
                    </div>

                    <button type="button" class="btn-action-jawab <?php echo $status_key; ?>" onclick='bukaModalJawab(<?php echo $json_konsul; ?>)'>
                        <?php if ($k['sudah_dijawab']): ?>
                            <span>✏️ Ubah / Lengkapi Jawaban</span>
                        <?php else: ?>
                            <span>💬 Jawab Konsultasi SBAR</span>
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
                        <th style="width: 40px;">No</th>
                        <th>Waktu & No. Konsul</th>
                        <th>No. Rawat / RM</th>
                        <th>Pasien</th>
                        <th>Lokasi</th>
                        <th>Perawat</th>
                        <th>Situasi (S) & Latar (B)</th>
                        <th>Rekomendasi / Jawaban (R)</th>
                        <th>Status</th>
                        <th style="text-align:center; width: 130px;">Aksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $no = 1;
                    foreach ($data_konsul as $k): 
                        $status_key = $k['sudah_dijawab'] ? 'sudah' : 'belum';
                        $badge_class = $k['sudah_dijawab'] ? 'badge-sudah' : 'badge-belum';
                        $status_text = $k['sudah_dijawab'] ? 'Sudah Dijawab' : 'Belum Dijawab';
                        $json_konsul = htmlspecialchars(json_encode($k), ENT_QUOTES, 'UTF-8');
                    ?>
                        <tr data-status="<?php echo $status_key; ?>" data-search="<?php echo strtolower($k['nm_pasien'] . ' ' . $k['no_rkm_medis'] . ' ' . $k['no_rawat'] . ' ' . $k['no_permintaan'] . ' ' . $k['lokasi'] . ' ' . $k['nm_perawat'] . ' ' . $k['situation']); ?>">
                            <td><?php echo $no++; ?></td>
                            <td>
                                <strong><?php echo date('d/m/Y H:i', strtotime($k['tanggal'])); ?></strong><br>
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
                            <td><?php echo htmlspecialchars($k['nm_perawat'] ?? $k['nip']); ?></td>
                            <td style="max-width: 220px;">
                                <div style="font-size:12px;">
                                    <strong style="color:#0284c7;">S:</strong> <?php echo htmlspecialchars(mb_strimwidth($k['situation'] ?? '-', 0, 75, '...')); ?><br>
                                    <strong style="color:#92400e;">B:</strong> <?php echo htmlspecialchars(mb_strimwidth($k['background'] ?? '-', 0, 75, '...')); ?>
                                </div>
                            </td>
                            <td style="max-width: 220px;">
                                <?php if ($k['sudah_dijawab']): ?>
                                    <span style="color:#15803d; font-weight:600; font-size:12px;"><?php echo htmlspecialchars(mb_strimwidth($k['recomendation'], 0, 100, '...')); ?></span>
                                <?php else: ?>
                                    <span style="color:var(--gray); font-style:italic; font-size:12px;">Menunggu instruksi dokter...</span>
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
            <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="margin-bottom:8px; color:#cbd5e1;"><path stroke-linecap="round" stroke-linejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/></svg>
            <h3 style="font-size: 16px; margin-bottom: 6px; color: #334155;">Tidak Ada Konsultasi</h3>
            <p style="font-size: 13px;">Belum ditemukan data konsultasi perawat yang ditujukan kepada Anda saat ini.</p>
        </div>
    <?php endif; ?>

</main>

<!-- Modal Jawab / Edit Konsultasi SBAR -->
<div id="modalJawab" class="modal">
    <div class="modal-content">
        <button type="button" class="modal-close" onclick="tutupModalJawab()">&times;</button>
        
        <h3 class="modal-header-title">💬 Jawab Konsultasi Perawat (SBAR)</h3>
        <p style="font-size: 12px; color: var(--gray); margin-bottom: 8px;">Lengkapi atau ubah instruksi medis dan rekomendasi konsultasi</p>

        <!-- Ringkasan Pasien & Pengirim -->
        <div class="patient-summary-box">
            <div>Pasien: <strong id="mdl_nama_pasien">-</strong></div>
            <div>No. RM: <strong id="mdl_no_rm">-</strong></div>
            <div>No. Rawat: <strong id="mdl_no_rawat" style="font-family:monospace;">-</strong></div>
            <div>Lokasi: <strong id="mdl_lokasi">-</strong></div>
            <div>Perawat: <strong id="mdl_perawat">-</strong></div>
            <div>Waktu: <strong id="mdl_tanggal">-</strong></div>
        </div>

        <form method="POST" action="" id="formKonsul">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="no_permintaan" id="mdl_no_permintaan">

            <div class="section-label">
                <span>📋</span> Metode Komunikasi SBAR
            </div>

            <!-- Situation -->
            <div class="form-field">
                <label>1. Situation (Kondisi saat ini / keluhan yang dilaporkan)</label>
                <textarea name="situation" id="mdl_situation" rows="2" placeholder="Situasi pasien saat dikonsulkan..."></textarea>
            </div>

            <!-- Background -->
            <div class="form-field">
                <label>2. Background (Latar belakang klinis, riwayat penyakit & diagnosa)</label>
                <textarea name="background" id="mdl_background" rows="2" placeholder="Riwayat penyakit, diagnosa awal, alergi..."></textarea>
            </div>

            <!-- Assessment -->
            <div class="form-field">
                <label>3. Assessment (Penilaian klinis perawat / hasil pemeriksaan penunjang)</label>
                <textarea name="assessment" id="mdl_assessment" rows="2" placeholder="Penilaian masalah keperawatan atau hasil lab terbaru..."></textarea>
            </div>

            <!-- Recommendation (Jawaban Dokter) -->
            <div class="form-field recom-highlight">
                <label style="color:#15803d; font-size:13px;">4. Recommendation (Instruksi Medis / Jawaban Dokter) <span style="color:#ef4444;">*</span></label>
                <textarea name="recomendation" id="mdl_recomendation" rows="4" placeholder="Tuliskan instruksi terapi obat, dosis, tindakan medis, atau rencana tindak lanjut..." required style="border-color:#86efac;"></textarea>
                <small style="color:var(--gray); margin-top:4px;">Berikan instruksi atau rekomendasi yang jelas untuk perawat pelaksana.</small>
            </div>

            <!-- Footer Action Buttons -->
            <div class="modal-action-footer">
                <button type="button" class="btn-cancel" onclick="tutupModalJawab()">Batal</button>
                <button type="submit" name="simpan_konsultasi" class="btn-submit">
                    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    <span>Simpan Jawaban Konsultasi</span>
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
        const cards = document.querySelectorAll('#konsulCards .konsul-card');
        const rows = document.querySelectorAll('#konsulTable tbody tr');

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

    // Modal Logic
    const modalJawab = document.getElementById('modalJawab');

    function bukaModalJawab(k) {
        document.getElementById('mdl_no_permintaan').value = k.no_permintaan || '';
        document.getElementById('mdl_nama_pasien').textContent = k.nm_pasien || '-';
        document.getElementById('mdl_no_rm').textContent = k.no_rkm_medis || '-';
        document.getElementById('mdl_no_rawat').textContent = k.no_rawat || '-';
        document.getElementById('mdl_lokasi').textContent = k.lokasi + (k.kd_kamar ? ' (' + k.kd_kamar + ')' : '');
        document.getElementById('mdl_perawat').textContent = k.nm_perawat || k.nip || '-';
        document.getElementById('mdl_tanggal').textContent = k.tanggal || '-';

        document.getElementById('mdl_situation').value = k.situation || '';
        document.getElementById('mdl_background').value = k.background || '';
        document.getElementById('mdl_assessment').value = k.assessment || '';
        document.getElementById('mdl_recomendation').value = (k.recomendation && k.recomendation !== '-') ? k.recomendation : '';

        modalJawab.style.display = 'block';
        document.body.style.overflow = 'hidden';

        setTimeout(() => {
            document.getElementById('mdl_recomendation').focus();
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
