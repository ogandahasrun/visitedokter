<?php
require_once 'auth.php';

// Hitung rekap pasien hari ini untuk 3 menu utama
$count_ralan = 0;
$count_ranap = 0;
$count_operasi = 0;

if ($is_super_admin) {
    // 1. Rawat Jalan Hari Ini
    $q1 = mysqli_query($koneksi, "SELECT COUNT(*) as total FROM reg_periksa WHERE tgl_registrasi = CURDATE() AND status_lanjut = 'Ralan'");
    if ($q1) {
        $count_ralan = (int)mysqli_fetch_assoc($q1)['total'];
    }

    // 2. Rawat Inap Aktif
    $q2 = mysqli_query($koneksi, "SELECT COUNT(DISTINCT dpjp_ranap.no_rawat) as total FROM dpjp_ranap INNER JOIN kamar_inap ON kamar_inap.no_rawat = dpjp_ranap.no_rawat WHERE kamar_inap.stts_pulang = '-'");
    if ($q2) {
        $count_ranap = (int)mysqli_fetch_assoc($q2)['total'];
    }

    // 3. Jadwal Operasi Hari Ini
    $q3 = mysqli_query($koneksi, "SELECT COUNT(*) as total FROM booking_operasi WHERE tanggal = CURDATE()");
    if ($q3) {
        $count_operasi = (int)mysqli_fetch_assoc($q3)['total'];
    }

    // 4. Konsultasi Perawat
    $count_konsul = 0;
    $q4 = mysqli_query($koneksi, "SELECT COUNT(*) as total FROM konsultasi_perawat");
    if ($q4) {
        $count_konsul = (int)mysqli_fetch_assoc($q4)['total'];
    }
} else if ($kd_dokter) {
    // 1. Rawat Jalan Hari Ini (Dokter)
    $stmt1 = mysqli_prepare($koneksi, "SELECT COUNT(*) as total FROM reg_periksa WHERE tgl_registrasi = CURDATE() AND status_lanjut = 'Ralan' AND kd_dokter = ?");
    if ($stmt1) {
        mysqli_stmt_bind_param($stmt1, "s", $kd_dokter);
        mysqli_stmt_execute($stmt1);
        $res1 = mysqli_stmt_get_result($stmt1);
        if ($row1 = mysqli_fetch_assoc($res1)) {
            $count_ralan = (int)$row1['total'];
        }
        mysqli_stmt_close($stmt1);
    }

    // 2. Rawat Inap Aktif (Dokter DPJP)
    $stmt2 = mysqli_prepare($koneksi, "SELECT COUNT(DISTINCT dpjp_ranap.no_rawat) as total FROM dpjp_ranap INNER JOIN kamar_inap ON kamar_inap.no_rawat = dpjp_ranap.no_rawat WHERE kamar_inap.stts_pulang = '-' AND dpjp_ranap.kd_dokter = ?");
    if ($stmt2) {
        mysqli_stmt_bind_param($stmt2, "s", $kd_dokter);
        mysqli_stmt_execute($stmt2);
        $res2 = mysqli_stmt_get_result($stmt2);
        if ($row2 = mysqli_fetch_assoc($res2)) {
            $count_ranap = (int)$row2['total'];
        }
        mysqli_stmt_close($stmt2);
    }

    // 3. Jadwal Operasi Hari Ini (Dokter)
    $stmt3 = mysqli_prepare($koneksi, "SELECT COUNT(*) as total FROM booking_operasi WHERE tanggal = CURDATE() AND kd_dokter = ?");
    if ($stmt3) {
        mysqli_stmt_bind_param($stmt3, "s", $kd_dokter);
        mysqli_stmt_execute($stmt3);
        $res3 = mysqli_stmt_get_result($stmt3);
        if ($row3 = mysqli_fetch_assoc($res3)) {
            $count_operasi = (int)$row3['total'];
        }
        mysqli_stmt_close($stmt3);
    }

    // 4. Konsultasi Perawat (Dokter yang dikonsuli)
    $count_konsul = 0;
    $stmt4 = mysqli_prepare($koneksi, "SELECT COUNT(*) as total FROM konsultasi_perawat WHERE kd_dokter_dikonsuli = ?");
    if ($stmt4) {
        mysqli_stmt_bind_param($stmt4, "s", $kd_dokter);
        mysqli_stmt_execute($stmt4);
        $res4 = mysqli_stmt_get_result($stmt4);
        if ($row4 = mysqli_fetch_assoc($res4)) {
            $count_konsul = (int)$row4['total'];
        }
        mysqli_stmt_close($stmt4);
    }
}

// Format tanggal Indonesia
$hari_list = ['Sunday' => 'Minggu', 'Monday' => 'Senin', 'Tuesday' => 'Selasa', 'Wednesday' => 'Rabu', 'Thursday' => 'Kamis', 'Friday' => 'Jumat', 'Saturday' => 'Sabtu'];
$bulan_list = [1 => 'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];

$hari_ini = $hari_list[date('l')];
$tgl_indo = date('j') . ' ' . $bulan_list[(int)date('n')] . ' ' . date('Y');
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Menu Utama - <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        :root {
            --bg-page: #f0f4f9;
            --text-dark: #0f172a;
            --text-muted: #64748b;
            --radius-lg: 20px;
            --radius-md: 14px;
            --shadow-card: 0 4px 16px rgba(15, 23, 42, 0.08);
            --shadow-hover: 0 8px 24px rgba(15, 23, 42, 0.12);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(180deg, #e0f2fe 0%, #f0f4f9 220px, #f0f4f9 100%);
            color: var(--text-dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.5;
        }

        /* Top Header */
        .header-top {
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            max-width: 680px;
            margin: 0 auto;
            width: 100%;
        }

        .brand-container {
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none;
            color: inherit;
        }

        .hospital-logo {
            width: 44px;
            height: 48px;
            object-fit: contain;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
        }

        .brand-text h1 {
            font-size: 17px;
            font-weight: 800;
            color: #0369a1;
            letter-spacing: -0.3px;
            line-height: 1.2;
        }

        .brand-text p {
            font-size: 11px;
            font-weight: 600;
            color: #0284c7;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-logout-icon {
            display: flex;
            align-items: center;
            gap: 6px;
            background: white;
            color: #ef4444;
            border: 1px solid #fecaca;
            padding: 8px 12px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            transition: all 0.2s;
        }
        .btn-logout-icon:active {
            transform: scale(0.95);
            background: #fee2e2;
        }

        /* Container */
        .content-wrap {
            max-width: 680px;
            width: 100%;
            margin: 0 auto;
            padding: 0 16px 24px;
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }

        /* Profile Welcome Card */
        .welcome-card {
            background: white;
            border-radius: var(--radius-lg);
            padding: 18px 20px;
            box-shadow: var(--shadow-card);
            border: 1px solid rgba(255, 255, 255, 0.8);
            display: flex;
            align-items: center;
            gap: 16px;
            position: relative;
            overflow: hidden;
        }

        .welcome-card::after {
            content: "";
            position: absolute;
            right: -20px;
            top: -20px;
            width: 100px;
            height: 100px;
            background: radial-gradient(circle, rgba(14, 165, 233, 0.15) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
        }

        .user-avatar {
            width: 52px;
            height: 52px;
            border-radius: 16px;
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            flex-shrink: 0;
            box-shadow: 0 4px 10px rgba(2, 132, 199, 0.3);
        }

        .welcome-info {
            flex: 1;
            min-width: 0;
        }

        .welcome-greeting {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .user-name {
            font-size: 17px;
            font-weight: 800;
            color: var(--text-dark);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin: 2px 0 4px;
        }

        .role-tag-row {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 6px;
        }

        .role-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }
        .role-badge.admin {
            background: #fee2e2;
            color: #dc2626;
        }
        .role-badge.dokter {
            background: #e0f2fe;
            color: #0284c7;
        }

        .time-chip {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 500;
        }

        /* Section Heading */
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 4px;
            padding: 0 4px;
        }

        .section-title {
            font-size: 14px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: #475569;
        }

        .today-chip {
            font-size: 12px;
            font-weight: 600;
            color: #0369a1;
            background: #e0f2fe;
            padding: 3px 10px;
            border-radius: 999px;
        }

        /* 3 Main Menu Cards Grid */
        .menu-grid {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .menu-card {
            background: white;
            border-radius: var(--radius-lg);
            padding: 18px 20px;
            text-decoration: none;
            color: inherit;
            display: flex;
            align-items: center;
            gap: 16px;
            box-shadow: var(--shadow-card);
            border: 1px solid #e2e8f0;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .menu-card:active {
            transform: scale(0.98);
        }

        .menu-card:hover {
            box-shadow: var(--shadow-hover);
            border-color: #cbd5e1;
        }

        /* Distinct theme colors for the 3 menus */
        /* 1. Rawat Jalan: Emerald Green */
        .menu-card.card-ralan {
            border-left: 6px solid #059669;
        }
        .menu-card.card-ralan .menu-icon-box {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        .menu-card.card-ralan .count-badge {
            background: #d1fae5;
            color: #065f46;
        }

        /* 2. Rawat Inap: Royal Sky Blue */
        .menu-card.card-ranap {
            border-left: 6px solid #0284c7;
        }
        .menu-card.card-ranap .menu-icon-box {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
        }
        .menu-card.card-ranap .count-badge {
            background: #e0f2fe;
            color: #075985;
        }

        /* 3. Jadwal Operasi: Vivid Violet */
        .menu-card.card-operasi {
            border-left: 6px solid #7c3aed;
        }
        .menu-card.card-operasi .menu-icon-box {
            background: linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%);
            box-shadow: 0 4px 12px rgba(124, 58, 237, 0.3);
        }
        .menu-card.card-operasi .count-badge {
            background: #ede9fe;
            color: #5b21b6;
        }

        /* 4. Konsultasi Perawat: Amber / Orange */
        .menu-card.card-konsul {
            border-left: 6px solid #f59e0b;
        }
        .menu-card.card-konsul .menu-icon-box {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
        }
        .menu-card.card-konsul .count-badge {
            background: #fef3c7;
            color: #92400e;
        }

        .menu-icon-box {
            width: 56px;
            height: 56px;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            flex-shrink: 0;
        }
        .menu-icon-box svg {
            width: 28px;
            height: 28px;
        }

        .menu-content {
            flex: 1;
            min-width: 0;
        }

        .menu-title-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            margin-bottom: 4px;
        }

        .menu-title {
            font-size: 18px;
            font-weight: 800;
            color: #0f172a;
        }

        .count-badge {
            font-size: 12px;
            font-weight: 700;
            padding: 3px 9px;
            border-radius: 999px;
            white-space: nowrap;
        }

        .menu-desc {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.35;
        }

        .menu-arrow {
            color: #94a3b8;
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s;
        }

        .menu-card:hover .menu-arrow {
            transform: translateX(4px);
            color: #0f172a;
        }

        /* Footer */
        footer {
            text-align: center;
            padding: 20px 16px;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: auto;
        }

        /* Media Queries */
        @media (min-width: 640px) {
            .menu-grid {
                gap: 16px;
            }
            .menu-card {
                padding: 20px 24px;
            }
        }
    </style>
</head>
<body>

<!-- Top Bar -->
<header class="header-top">
    <a href="index.php" class="brand-container">
        <img src="<?php echo $logo_src; ?>" alt="Logo" class="hospital-logo">
        <div class="brand-text">
            <h1><?php echo htmlspecialchars($nama_instansi); ?></h1>
            <p>Sistem Layanan Dokter</p>
        </div>
    </a>
    <form method="POST" action="logout.php" style="margin:0;">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <button type="submit" class="btn-logout-icon" title="Keluar dari sistem" onclick="return confirm('Apakah Anda yakin ingin logout?');">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
            <span>Keluar</span>
        </button>
    </form>
</header>

<main class="content-wrap">
    <!-- User Profile Card -->
    <div class="welcome-card">
        <div class="user-avatar">
            👨‍⚕️
        </div>
        <div class="welcome-info">
            <div class="welcome-greeting">Selamat Datang</div>
            <div class="user-name" title="<?php echo htmlspecialchars($nama_pegawai); ?>">
                <?php echo htmlspecialchars($nama_pegawai); ?>
            </div>
            <div class="role-tag-row">
                <?php if ($is_super_admin): ?>
                    <span class="role-badge admin">SUPER ADMIN</span>
                <?php else: ?>
                    <span class="role-badge dokter">DOKTER DPJP</span>
                <?php endif; ?>
                <span class="time-chip">
                    <?php echo $hari_ini; ?>, <?php echo $tgl_indo; ?> &bull; <span id="clockDisplay"><?php echo date('H:i'); ?></span> WIB
                </span>
            </div>
        </div>
    </div>

    <!-- Section Heading -->
    <div class="section-header">
        <span class="section-title">Menu Utama</span>
        <span class="today-chip">Hari Ini</span>
    </div>

    <!-- The 3 Primary Menus -->
    <div class="menu-grid">
        <!-- 1. Rawat Jalan -->
        <a href="rawat_jalan.php" class="menu-card card-ralan">
            <div class="menu-icon-box">
                <!-- Stethoscope / Outpatient Icon -->
                <svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
                    <path d="M4.5 3h15M6 3v5a6 6 0 0 0 12 0V3M12 14v4a4 4 0 0 0 4 4h1a2 2 0 0 0 2-2v-1.5a1.5 1.5 0 0 0-3 0v1.5"/>
                    <circle cx="12" cy="14" r="1.5" fill="currentColor"/>
                </svg>
            </div>
            <div class="menu-content">
                <div class="menu-title-row">
                    <span class="menu-title">Rawat Jalan</span>
                    <span class="count-badge"><?php echo $count_ralan; ?> Pasien</span>
                </div>
                <div class="menu-desc">
                    Pemeriksaan poliklinik, antrian pasien hari ini & status pemeriksaan
                </div>
            </div>
            <div class="menu-arrow">
                <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M9 18l6-6-6-6"/></svg>
            </div>
        </a>

        <!-- 2. Rawat Inap -->
        <a href="rawat_inap.php" class="menu-card card-ranap">
            <div class="menu-icon-box">
                <!-- Bed / Inpatient Icon -->
                <svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
                    <path d="M3 7v11M21 18V7M3 13h18M3 17h18"/>
                    <circle cx="7" cy="10" r="2"/>
                    <path d="M9 13v-3a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v3"/>
                </svg>
            </div>
            <div class="menu-content">
                <div class="menu-title-row">
                    <span class="menu-title">Rawat Inap</span>
                    <span class="count-badge"><?php echo $count_ranap; ?> Pasien</span>
                </div>
                <div class="menu-desc">
                    Visite pasien DPJP aktif, rekap pemeriksaan harian & pasien baru
                </div>
            </div>
            <div class="menu-arrow">
                <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M9 18l6-6-6-6"/></svg>
            </div>
        </a>

        <!-- 3. Jadwal Operasi -->
        <a href="jadwal_operasi.php" class="menu-card card-operasi">
            <div class="menu-icon-box">
                <!-- Scalpel / Operating Theater Icon -->
                <svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
                    <path d="M14.5 4l5.5 5.5-12 12L2 22l.5-6 12-12z"/>
                    <path d="M18 7.5l-2-2"/>
                    <circle cx="18" cy="18" r="3"/>
                    <path d="M18 15v6M15 18h6"/>
                </svg>
            </div>
            <div class="menu-content">
                <div class="menu-title-row">
                    <span class="menu-title">Jadwal Operasi</span>
                    <span class="count-badge"><?php echo $count_operasi; ?> Jadwal</span>
                </div>
                <div class="menu-desc">
                    Jadwal & booking kamar operasi (OK), paket tindakan & operator
                </div>
            </div>
            <div class="menu-arrow">
                <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M9 18l6-6-6-6"/></svg>
            </div>
        </a>

        <!-- 4. Konsultasi Perawat -->
        <a href="konsultasi_perawat.php" class="menu-card card-konsul">
            <div class="menu-icon-box">
                <!-- Chat / Consultation SBAR Icon -->
                <svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
                    <path d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/>
                </svg>
            </div>
            <div class="menu-content">
                <div class="menu-title-row">
                    <span class="menu-title">Konsultasi Perawat</span>
                    <span class="count-badge"><?php echo $count_konsul; ?> Konsul</span>
                </div>
                <div class="menu-desc">
                    Jawab & verifikasi rekomendasi konsultasi metode SBAR dari perawat
                </div>
            </div>
            <div class="menu-arrow">
                <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M9 18l6-6-6-6"/></svg>
            </div>
        </a>
    </div>
</main>

<footer>
    &copy; <?php echo date('Y'); ?> IT <?php echo htmlspecialchars($nama_instansi); ?><br>
    Sistem Informasi Pelayanan Pasien
</footer>

<script>
    // Live Clock
    setInterval(function() {
        const d = new Date();
        const h = String(d.getHours()).padStart(2, '0');
        const m = String(d.getMinutes()).padStart(2, '0');
        const el = document.getElementById('clockDisplay');
        if (el) el.textContent = `${h}:${m}`;
    }, 1000);
</script>

</body>
</html>