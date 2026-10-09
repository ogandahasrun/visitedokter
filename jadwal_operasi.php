<?php
require_once 'auth.php';

// Filter tanggal (default hari ini)
$tanggal = isset($_GET['tanggal']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['tanggal']) 
    ? $_GET['tanggal'] 
    : date('Y-m-d');

$data_operasi = array();

if ($is_super_admin) {
    $query = "SELECT 
        booking_operasi.no_rawat,
        booking_operasi.kode_paket,
        COALESCE(paket_operasi.nm_perawatan, booking_operasi.kode_paket) as nm_perawatan,
        booking_operasi.tanggal,
        booking_operasi.jam_mulai,
        booking_operasi.jam_selesai,
        booking_operasi.status,
        booking_operasi.kd_dokter,
        dokter.nm_dokter,
        reg_periksa.no_rkm_medis,
        pasien.nm_pasien,
        penjab.png_jawab,
        COALESCE(ruang_ok.nm_ruang_ok, booking_operasi.kd_ruang_ok, '-') as nm_ruang_ok
    FROM booking_operasi
    INNER JOIN reg_periksa ON booking_operasi.no_rawat = reg_periksa.no_rawat
    INNER JOIN pasien ON reg_periksa.no_rkm_medis = pasien.no_rkm_medis
    INNER JOIN penjab ON reg_periksa.kd_pj = penjab.kd_pj
    INNER JOIN dokter ON booking_operasi.kd_dokter = dokter.kd_dokter
    LEFT JOIN paket_operasi ON booking_operasi.kode_paket = paket_operasi.kode_paket
    LEFT JOIN ruang_ok ON booking_operasi.kd_ruang_ok = ruang_ok.kd_ruang_ok
    WHERE booking_operasi.tanggal = ?
    ORDER BY booking_operasi.jam_mulai ASC";

    $stmt = mysqli_prepare($koneksi, $query);
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $tanggal);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        while ($row = mysqli_fetch_assoc($res)) {
            $data_operasi[] = $row;
        }
        mysqli_stmt_close($stmt);
    }
} else if ($kd_dokter) {
    $query = "SELECT 
        booking_operasi.no_rawat,
        booking_operasi.kode_paket,
        COALESCE(paket_operasi.nm_perawatan, booking_operasi.kode_paket) as nm_perawatan,
        booking_operasi.tanggal,
        booking_operasi.jam_mulai,
        booking_operasi.jam_selesai,
        booking_operasi.status,
        booking_operasi.kd_dokter,
        dokter.nm_dokter,
        reg_periksa.no_rkm_medis,
        pasien.nm_pasien,
        penjab.png_jawab,
        COALESCE(ruang_ok.nm_ruang_ok, booking_operasi.kd_ruang_ok, '-') as nm_ruang_ok
    FROM booking_operasi
    INNER JOIN reg_periksa ON booking_operasi.no_rawat = reg_periksa.no_rawat
    INNER JOIN pasien ON reg_periksa.no_rkm_medis = pasien.no_rkm_medis
    INNER JOIN penjab ON reg_periksa.kd_pj = penjab.kd_pj
    INNER JOIN dokter ON booking_operasi.kd_dokter = dokter.kd_dokter
    LEFT JOIN paket_operasi ON booking_operasi.kode_paket = paket_operasi.kode_paket
    LEFT JOIN ruang_ok ON booking_operasi.kd_ruang_ok = ruang_ok.kd_ruang_ok
    WHERE booking_operasi.tanggal = ?
      AND booking_operasi.kd_dokter = ?
    ORDER BY booking_operasi.jam_mulai ASC";

    $stmt = mysqli_prepare($koneksi, $query);
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "ss", $tanggal, $kd_dokter);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        while ($row = mysqli_fetch_assoc($res)) {
            $data_operasi[] = $row;
        }
        mysqli_stmt_close($stmt);
    }
}

// Statistik
$total_ok = count($data_operasi);
$menunggu_ok = 0;
$proses_ok = 0;
$selesai_ok = 0;

foreach ($data_operasi as $op) {
    $st = strtolower($op['status']);
    if (strpos($st, 'selesai') !== false) {
        $selesai_ok++;
    } else if (strpos($st, 'proses') !== false) {
        $proses_ok++;
    } else {
        $menunggu_ok++;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Jadwal Operasi - <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        :root {
            --primary: #8b5cf6;
            --primary-dark: #7c3aed;
            --primary-light: #ede9fe;
            --success: #16a34a;
            --warning: #ea580c;
            --info: #0284c7;
            --dark: #1e293b;
            --gray: #64748b;
            --card-border: #e2e8f0;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
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

        .top-navbar {
            background: linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%);
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

        .meta-doctor strong {
            color: var(--primary-dark);
            font-size: 15px;
        }

        .date-picker-form {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .date-input {
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid #cbd5e1;
            font-size: 13px;
        }
        .btn-filter-date {
            background: var(--primary);
            color: white;
            border: none;
            padding: 7px 12px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            font-weight: 600;
        }

        /* Stats Grid */
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

        .stat-total .stat-num { color: #7c3aed; }
        .stat-total .stat-label { color: #6d28d9; }

        .stat-menunggu .stat-num { color: #d97706; }
        .stat-menunggu .stat-label { color: #b45309; }

        .stat-proses .stat-num { color: #2563eb; }
        .stat-proses .stat-label { color: #1d4ed8; }

        .stat-selesai .stat-num { color: #16a34a; }
        .stat-selesai .stat-label { color: #15803d; }

        /* Toolbar */
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

        /* Operation Cards (Mobile) */
        .op-cards {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .op-card {
            background: white;
            border-radius: var(--radius);
            padding: 16px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--card-border);
            border-left: 5px solid #94a3b8;
        }

        .op-card.status-selesai {
            border-left-color: #16a34a;
            background: linear-gradient(to right, #f0fdf4 0%, #ffffff 8%);
        }
        .op-card.status-proses {
            border-left-color: #2563eb;
            background: linear-gradient(to right, #eff6ff 0%, #ffffff 8%);
        }
        .op-card.status-menunggu {
            border-left-color: #f59e0b;
            background: linear-gradient(to right, #fffbeb 0%, #ffffff 8%);
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
        }
        .badge-selesai { background: #dcfce7; color: #166534; }
        .badge-proses { background: #dbeafe; color: #1e40af; }
        .badge-menunggu { background: #fef3c7; color: #92400e; }

        .time-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: #ede9fe;
            color: #6d28d9;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 12px;
        }

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
        }

        /* Table View */
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
            .card-info-grid {
                grid-template-columns: 1fr;
            }
            .main-container {
                padding: 12px;
            }
        }

        @media (min-width: 860px) {
            .table-responsive.show-desktop {
                display: block;
            }
            .op-cards.hide-desktop {
                display: none;
            }
        }
    </style>
</head>
<body>

<header class="top-navbar">
    <div class="navbar-content">
        <div class="nav-left">
            <a href="index.php" class="btn-back">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
                <span>Menu Utama</span>
            </a>
            <div class="header-title-box">
                <h1>Jadwal Operasi (OK)</h1>
                <p><?php echo htmlspecialchars($nama_instansi); ?></p>
            </div>
        </div>
        <div>
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
    <div class="meta-card">
        <div class="meta-doctor">
            Dokter Operator: <strong><?php echo htmlspecialchars($nama_pegawai); ?></strong>
            <?php if ($is_super_admin): ?>
                <span style="background: #fee2e2; color: #dc2626; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; margin-left: 6px;">SUPER ADMIN</span>
            <?php elseif ($kd_dokter): ?>
                <span style="color: var(--gray); font-size: 12px; margin-left: 6px;">(<?php echo htmlspecialchars($kd_dokter); ?>)</span>
            <?php endif; ?>
        </div>
        <form method="GET" class="date-picker-form">
            <input type="date" name="tanggal" value="<?php echo htmlspecialchars($tanggal); ?>" class="date-input">
            <button type="submit" class="btn-filter-date">Tampilkan</button>
        </form>
    </div>

    <!-- Stats -->
    <div class="stats-grid">
        <div class="stat-card stat-total active" onclick="filterByStatus('all')">
            <div class="stat-num"><?php echo $total_ok; ?></div>
            <div class="stat-label">Total Operasi</div>
        </div>
        <div class="stat-card stat-menunggu" onclick="filterByStatus('menunggu')">
            <div class="stat-num"><?php echo $menunggu_ok; ?></div>
            <div class="stat-label">Menunggu</div>
        </div>
        <div class="stat-card stat-proses" onclick="filterByStatus('proses')">
            <div class="stat-num"><?php echo $proses_ok; ?></div>
            <div class="stat-label">Sedang Proses</div>
        </div>
        <div class="stat-card stat-selesai" onclick="filterByStatus('selesai')">
            <div class="stat-num"><?php echo $selesai_ok; ?></div>
            <div class="stat-label">Selesai</div>
        </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
        <div class="search-box">
            <input type="text" id="searchInput" class="search-input" placeholder="🔍 Cari pasien, No RM, tindakan operasi, ruang OK..." onkeyup="filterOps()">
        </div>
        <div class="view-toggle">
            <button type="button" class="toggle-btn active" id="btnCardView" onclick="setViewMode('card')">📱 Kartu</button>
            <button type="button" class="toggle-btn" id="btnTableView" onclick="setViewMode('table')">📋 Tabel</button>
        </div>
    </div>

    <?php if (count($data_operasi) > 0): ?>
        <!-- Mobile Card View -->
        <div class="op-cards hide-desktop" id="opCards">
            <?php 
            foreach ($data_operasi as $op): 
                $st = strtolower($op['status']);
                if (strpos($st, 'selesai') !== false) {
                    $status_key = 'selesai';
                    $badge_class = 'badge-selesai';
                    $card_class = 'status-selesai';
                } else if (strpos($st, 'proses') !== false) {
                    $status_key = 'proses';
                    $badge_class = 'badge-proses';
                    $card_class = 'status-proses';
                } else {
                    $status_key = 'menunggu';
                    $badge_class = 'badge-menunggu';
                    $card_class = 'status-menunggu';
                }
            ?>
                <div class="op-card <?php echo $card_class; ?>" data-status="<?php echo $status_key; ?>" data-search="<?php echo strtolower($op['nm_pasien'] . ' ' . $op['no_rkm_medis'] . ' ' . $op['no_rawat'] . ' ' . $op['nm_perawatan'] . ' ' . $op['nm_ruang_ok']); ?>">
                    <div class="card-header-row">
                        <div>
                            <div class="time-badge">
                                ⏱️ <?php echo substr($op['jam_mulai'], 0, 5); ?> - <?php echo substr($op['jam_selesai'], 0, 5); ?> WIB
                            </div>
                            <div class="patient-name" style="margin-top: 6px;"><?php echo htmlspecialchars($op['nm_pasien']); ?></div>
                        </div>
                        <span class="status-badge <?php echo $badge_class; ?>"><?php echo htmlspecialchars($op['status']); ?></span>
                    </div>

                    <div class="card-info-grid">
                        <div class="info-item" style="grid-column: 1 / -1;">
                            <span class="info-label">Tindakan / Paket Operasi</span>
                            <span class="info-val" style="color: #6d28d9; font-size: 14px;">✂️ <?php echo htmlspecialchars($op['nm_perawatan']); ?></span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">No. Rekam Medis</span>
                            <span class="info-val"><?php echo htmlspecialchars($op['no_rkm_medis']); ?></span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Ruang Operasi (OK)</span>
                            <span class="info-val">🏥 <?php echo htmlspecialchars($op['nm_ruang_ok']); ?></span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">No. Rawat</span>
                            <span class="info-val"><?php echo htmlspecialchars($op['no_rawat']); ?></span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Penjamin</span>
                            <span class="info-val"><?php echo htmlspecialchars($op['png_jawab']); ?></span>
                        </div>
                        <?php if ($is_super_admin): ?>
                        <div class="info-item" style="grid-column: 1 / -1;">
                            <span class="info-label">Dokter Operator</span>
                            <span class="info-val">👨‍⚕️ <?php echo htmlspecialchars($op['nm_dokter']); ?></span>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Desktop Table View -->
        <div class="table-responsive show-desktop" id="opTable">
            <table>
                <thead>
                    <tr>
                        <th>Jam</th>
                        <th>No. Rawat</th>
                        <th>No. RM</th>
                        <th>Nama Pasien</th>
                        <th>Tindakan Operasi</th>
                        <th>Ruang OK</th>
                        <th>Penjamin</th>
                        <?php if ($is_super_admin): ?>
                            <th>Dokter Operator</th>
                        <?php endif; ?>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    foreach ($data_operasi as $op): 
                        $st = strtolower($op['status']);
                        if (strpos($st, 'selesai') !== false) {
                            $status_key = 'selesai';
                            $badge = '<span class="status-badge badge-selesai">' . htmlspecialchars($op['status']) . '</span>';
                        } else if (strpos($st, 'proses') !== false) {
                            $status_key = 'proses';
                            $badge = '<span class="status-badge badge-proses">' . htmlspecialchars($op['status']) . '</span>';
                        } else {
                            $status_key = 'menunggu';
                            $badge = '<span class="status-badge badge-menunggu">' . htmlspecialchars($op['status']) . '</span>';
                        }
                    ?>
                        <tr data-status="<?php echo $status_key; ?>" data-search="<?php echo strtolower($op['nm_pasien'] . ' ' . $op['no_rkm_medis'] . ' ' . $op['no_rawat'] . ' ' . $op['nm_perawatan'] . ' ' . $op['nm_ruang_ok']); ?>">
                            <td><span class="time-badge"><?php echo substr($op['jam_mulai'], 0, 5); ?> - <?php echo substr($op['jam_selesai'], 0, 5); ?></span></td>
                            <td><strong><?php echo htmlspecialchars($op['no_rawat']); ?></strong></td>
                            <td><?php echo htmlspecialchars($op['no_rkm_medis']); ?></td>
                            <td><strong><?php echo htmlspecialchars($op['nm_pasien']); ?></strong></td>
                            <td><span style="color: #6d28d9; font-weight: 700;"><?php echo htmlspecialchars($op['nm_perawatan']); ?></span></td>
                            <td><?php echo htmlspecialchars($op['nm_ruang_ok']); ?></td>
                            <td><?php echo htmlspecialchars($op['png_jawab']); ?></td>
                            <?php if ($is_super_admin): ?>
                                <td><?php echo htmlspecialchars($op['nm_dokter']); ?></td>
                            <?php endif; ?>
                            <td><?php echo $badge; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <div class="empty-box">
            <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
            <h3 style="font-size: 16px; margin-bottom: 6px; color: #334155;">Tidak Ada Jadwal Operasi</h3>
            <p style="font-size: 13px;">Tidak ditemukan booking operasi untuk tanggal <?php echo date('d/m/Y', strtotime($tanggal)); ?>.</p>
        </div>
    <?php endif; ?>
</main>

<footer>
    &copy; <?php echo date('Y'); ?> IT <?php echo htmlspecialchars($nama_instansi); ?> &bull; Sistem Kamar Operasi (OK)
</footer>

<script>
    let currentFilterStatus = 'all';

    function setViewMode(mode) {
        const cardContainer = document.getElementById('opCards');
        const tableContainer = document.getElementById('opTable');
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
        if (status === 'menunggu') document.querySelector('.stat-menunggu').classList.add('active');
        if (status === 'proses') document.querySelector('.stat-proses').classList.add('active');
        if (status === 'selesai') document.querySelector('.stat-selesai').classList.add('active');

        filterOps();
    }

    function filterOps() {
        const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
        
        const cards = document.querySelectorAll('#opCards .op-card');
        const rows = document.querySelectorAll('#opTable tbody tr');

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
</script>

</body>
</html>
