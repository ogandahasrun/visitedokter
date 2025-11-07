<?php
// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

session_start();

// Set timezone Indonesia (Jakarta) untuk memastikan tanggal yang benar
date_default_timezone_set('Asia/Jakarta');

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['regenerated'])) {
    session_regenerate_id(true);
    $_SESSION['regenerated'] = true;
}

include 'koneksi.php';

// Check if user is logged in
if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
    session_destroy();
    header('Location: login.php');
    exit();
}

// Validate session timeout (optional - 1 hour)
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 3600)) {
    session_unset();
    session_destroy();
    header('Location: login.php?timeout=1');
    exit();
}
$_SESSION['last_activity'] = time();

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Ambil data instansi dari database
$query_instansi = "SELECT nama_instansi, logo FROM setting LIMIT 1";
$result_instansi = mysqli_query($koneksi, $query_instansi);
$nama_instansi = "RSUD PRINGSEWU";
$logo_src = "images/logo.png"; // default jika tidak ada di database

if ($row_instansi = mysqli_fetch_assoc($result_instansi)) {
    $nama_instansi = $row_instansi['nama_instansi'];
    if (!empty($row_instansi['logo'])) {
        // Konversi BLOB ke base64
        $logo_blob = $row_instansi['logo'];
        $logo_base64 = base64_encode($logo_blob);
        $logo_src = "data:image/png;base64," . $logo_base64;
    }
}

// Sanitize and validate username input
$username = filter_var(trim($_SESSION['username']), FILTER_SANITIZE_STRING);

if (empty($username) || strlen($username) > 50) {
    session_destroy();
    header('Location: login.php?error=invalid_session');
    exit();
}

// Ambil nama pegawai berdasarkan username (NIK) yang login
$query_pegawai = "SELECT nama FROM pegawai WHERE nik = ? LIMIT 1";
$stmt = mysqli_prepare($koneksi, $query_pegawai);

if ($stmt === false) {
    error_log('Database prepare failed: ' . mysqli_error($koneksi));
    die('Database error occurred. Please try again later.');
}

mysqli_stmt_bind_param($stmt, "s", $username);
mysqli_stmt_execute($stmt);
$result_pegawai = mysqli_stmt_get_result($stmt);
$nama_pegawai = $username; // default jika tidak ditemukan

if ($row_pegawai = mysqli_fetch_assoc($result_pegawai)) {
    $nama_pegawai = $row_pegawai['nama'];
}
mysqli_stmt_close($stmt);

// Ambil kd_dokter berdasarkan username yang login (asumsi username = kd_dokter)
// Atau bisa juga menggunakan kolom lain yang sesuai dengan struktur database
$query_dokter = "SELECT kd_dokter FROM dokter WHERE kd_dokter = ? LIMIT 1";
$stmt_dokter = mysqli_prepare($koneksi, $query_dokter);

if ($stmt_dokter === false) {
    error_log('Database prepare failed for dokter query: ' . mysqli_error($koneksi));
    // Jika query gagal, coba dengan asumsi langsung bahwa username = kd_dokter (dengan validasi)
    $kd_dokter = preg_match('/^[A-Za-z0-9_-]+$/', $username) ? $username : null;
} else {
    mysqli_stmt_bind_param($stmt_dokter, "s", $username);
    mysqli_stmt_execute($stmt_dokter);
    $result_dokter = mysqli_stmt_get_result($stmt_dokter);
    $kd_dokter = null;

    if ($row_dokter = mysqli_fetch_assoc($result_dokter)) {
        $kd_dokter = $row_dokter['kd_dokter'];
    } else {
        // Jika tidak ditemukan, coba asumsi langsung username = kd_dokter (dengan validasi)
        $kd_dokter = preg_match('/^[A-Za-z0-9_-]+$/', $username) ? $username : null;
    }
    mysqli_stmt_close($stmt_dokter);
}

// Query untuk mengambil data pasien DPJP dengan status pemeriksaan hari ini
// Pastikan timezone sudah di-set untuk tanggal yang akurat
$tanggal_hari_ini = date('Y-m-d');
$data_pasien = array();

// Cek apakah user adalah super admin (ID = 170985)
$is_super_admin = ($username == '170985');

// Jika super admin, ambil semua data. Jika dokter biasa, hanya data mereka
if ($is_super_admin || $kd_dokter) {
    
    if ($is_super_admin) {
        // Query untuk super admin - melihat SEMUA data pasien rawat inap
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
                    AND pemeriksaan_ranap.nip IN (
                        SELECT dokter.kd_dokter 
                        FROM dokter 
                        INNER JOIN dpjp_ranap d ON dokter.kd_dokter = d.kd_dokter 
                        WHERE d.no_rawat = dpjp_ranap.no_rawat
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
        ORDER BY dokter.nm_dokter";
    } else {
        // Query untuk dokter biasa - hanya data pasien mereka
        $query_pasien = "SELECT DISTINCT
            dpjp_ranap.no_rawat,
            reg_periksa.no_rkm_medis,
            pasien.nm_pasien,
            penjab.png_jawab,            
            kamar_inap.diagnosa_awal,
            kamar.kd_kamar,
            bangsal.nm_bangsal,
            CASE 
                WHEN EXISTS (
                    SELECT 1 FROM pemeriksaan_ranap 
                    WHERE pemeriksaan_ranap.no_rawat = dpjp_ranap.no_rawat 
                    AND pemeriksaan_ranap.nip = ?
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
    
    if ($stmt_pasien === false) {
        error_log('Database prepare failed for pasien query: ' . mysqli_error($koneksi));
        die('Database error occurred. Please try again later.');
    }
    
    if ($is_super_admin) {
        // Super admin hanya perlu parameter tanggal
        mysqli_stmt_bind_param($stmt_pasien, "s", $tanggal_hari_ini);
    } else {
        // Dokter biasa perlu parameter nip, tanggal, dan kd_dokter
        mysqli_stmt_bind_param($stmt_pasien, "sss", $username, $tanggal_hari_ini, $kd_dokter);
    }
    mysqli_stmt_execute($stmt_pasien);
    $result_pasien = mysqli_stmt_get_result($stmt_pasien);
    
    while ($row = mysqli_fetch_assoc($result_pasien)) {
        $data_pasien[] = $row;
    }
    mysqli_stmt_close($stmt_pasien);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo htmlspecialchars($nama_instansi); ?> - Dashboard</title>
<style>
    body {
        background: linear-gradient(to right, #00c6ff, #0072ff);
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 0;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }
    .logo-container {
        text-align: center;
        margin-bottom: 30px;
        margin-top: 30px;
    }
    .logo-container img {
        border-radius: 10px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    .instansi-name {
        font-size: 24px;
        font-weight: bold;
        color: white;
        margin-top: 15px;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    .container {
        max-width: 800px;
        margin: 0 auto;
        padding: 30px;
        background: white;
        border-radius: 10px;
        box-shadow: 0 0 20px rgba(0,0,0,0.2);
        flex: 1;
        margin-bottom: 30px;
    }
    .container h1 {
        text-align: center;
        color: #333;
        margin-bottom: 20px;
    }
    .container p {
        font-size: 18px;
        color: #666;
        text-align: center;
        margin-bottom: 30px;
    }
    .logout {
        display: block;
        width: 200px;
        margin: 0 auto;
        padding: 12px;
        background: #dc3545;
        color: white;
        text-decoration: none;
        text-align: center;
        border-radius: 5px;
        font-size: 16px;
        transition: background 0.3s;
    }
    .logout:hover {
        background: #c82333;
    }
    footer {
        background: rgba(255,255,255,0.1);
        color: white;
        text-align: center;
        padding: 15px;
        margin-top: auto;
        text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
    }
    .table-container {
        margin: 20px 0;
        overflow-x: auto;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }
    table th, table td {
        padding: 12px;
        text-align: left;
        border: 1px solid #ddd;
    }
    table th {
        background-color: #007bff;
        color: white;
        font-weight: bold;
    }
    .sudah-periksa {
        background-color: #d4edda !important;
        color: #155724;
    }
    .belum-periksa {
        background-color: #f8f9fa !important;
        color: #495057;
    }
    .pasien-baru {
        background-color: #cce7ff !important;
        color: #004085;
    }
    .info-box {
        background: #e7f3ff;
        border: 1px solid #b3d9ff;
        padding: 15px;
        margin: 20px 0;
        border-radius: 5px;
        text-align: center;
    }
    .status-legend {
        display: flex;
        justify-content: center;
        gap: 20px;
        margin: 15px 0;
        flex-wrap: wrap;
    }
    .legend-item {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .legend-color {
        width: 20px;
        height: 20px;
        border: 1px solid #ccc;
        border-radius: 3px;
    }
    .legend-hijau {
        background-color: #d4edda;
    }
    .legend-putih {
        background-color: #f8f9fa;
    }
    .legend-biru {
        background-color: #cce7ff;
    }
</style>
</head>
<body>

<div class="logo-container">
    <a href="index.php">
        <img src="<?php echo $logo_src; ?>" alt="Logo" width="100" height="120">
    </a>
    <div class="instansi-name"><?php echo htmlspecialchars($nama_instansi); ?></div>
</div>

<div class="container">
    <h1>Dashboard DPJP</h1>
    <p>Selamat Datang, <?php echo htmlspecialchars($nama_pegawai); ?>!</p>
    
    <?php if ($is_super_admin || $kd_dokter): ?>
        <div class="info-box">
            <strong>Tanggal:</strong> <?php echo date('d/m/Y'); ?> | 
            <strong>Waktu:</strong> <?php echo date('H:i:s'); ?> | 
            <strong>Timezone:</strong> <?php echo date_default_timezone_get(); ?><br>
            <?php if ($is_super_admin): ?>
                <strong>Status:</strong> <span style="color: #dc3545; font-weight: bold;">SUPER ADMIN - Akses Semua Data</span> |
                <strong>Total Pasien Rawat Inap:</strong> <?php echo count($data_pasien); ?>
            <?php else: ?>
                <strong>Kode Dokter:</strong> <?php echo htmlspecialchars($kd_dokter); ?> |
                <strong>Total Pasien:</strong> <?php echo count($data_pasien); ?>
            <?php endif; ?>
        </div>
        
        <div class="status-legend">
            <div class="legend-item">
                <div class="legend-color legend-hijau"></div>
                <span>Sudah Diperiksa Hari Ini</span>
            </div>
            <div class="legend-item">
                <div class="legend-color legend-putih"></div>
                <span>Belum Diperiksa Hari Ini</span>
            </div>
            <div class="legend-item">
                <div class="legend-color legend-biru"></div>
                <span>Pasien Baru Masuk Hari Ini</span>
            </div>
        </div>

        <?php if (count($data_pasien) > 0): ?>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>No</th>
                            <th>No. Rawat</th>
                            <th>No. RM</th>
                            <th>Nama Pasien</th>
                            <th>Penjamin</th>
                            <?php if ($is_super_admin): ?>
                                <th>Kode Dokter</th>
                                <th>Nama Dokter</th>
                            <?php endif; ?>
                            <th>Bangsal</th>
                            <th>Kamar</th>
                            <th>Diagnosa Awal</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php 
                        $no = 1;
                        foreach ($data_pasien as $pasien): 
                            // Prioritas pewarnaan: Pasien baru (biru) > Sudah periksa (hijau) > Belum periksa (putih)
                            if ($pasien['pasien_baru_hari_ini']) {
                                $class = 'pasien-baru';
                                $status = $pasien['sudah_periksa'] ? 'Sudah Diperiksa (Pasien Baru)' : 'Belum Diperiksa (Pasien Baru)';
                            } else {
                                $class = $pasien['sudah_periksa'] ? 'sudah-periksa' : 'belum-periksa';
                                $status = $pasien['sudah_periksa'] ? 'Sudah Diperiksa' : 'Belum Diperiksa';
                            }
                        ?>
                            <tr class="<?php echo $class; ?>">
                                <td><?php echo $no++; ?></td>
                                <td><?php echo htmlspecialchars($pasien['no_rawat']); ?></td>
                                <td><?php echo htmlspecialchars($pasien['no_rkm_medis']); ?></td>
                                <td><?php echo htmlspecialchars($pasien['nm_pasien']); ?></td>
                                <td><?php echo htmlspecialchars($pasien['png_jawab']); ?></td>
                                <?php if ($is_super_admin): ?>
                                    <td><?php echo htmlspecialchars($pasien['kd_dokter']); ?></td>
                                    <td><?php echo htmlspecialchars($pasien['nm_dokter']); ?></td>
                                <?php endif; ?>
                                <td><?php echo htmlspecialchars($pasien['nm_bangsal']); ?></td>
                                <td><?php echo htmlspecialchars($pasien['kd_kamar']); ?></td>
                                <td><?php echo htmlspecialchars($pasien['diagnosa_awal']); ?></td>
                                <td><?php echo $status; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="info-box">
                <p>Tidak ada pasien yang menjadi tanggung jawab Anda saat ini.</p>
            </div>
        <?php endif; ?>
    <?php else: ?>
        <div class="info-box">
            <?php if ($is_super_admin): ?>
                <p>Selamat datang Super Admin! Sistem siap menampilkan semua data pasien rawat inap.</p>
            <?php else: ?>
                <p>Anda tidak terdaftar sebagai dokter dalam sistem.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="logout.php" style="display: inline;">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <button type="submit" class="logout" style="border: none; cursor: pointer;">Logout</button>
    </form>
</div>

<footer>by IT <?php echo htmlspecialchars($nama_instansi); ?></footer>

</body>
</html>
