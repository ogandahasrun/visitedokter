<?php
// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Set timezone Indonesia (Jakarta)
date_default_timezone_set('Asia/Jakarta');

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['regenerated'])) {
    session_regenerate_id(true);
    $_SESSION['regenerated'] = true;
}

// Validate database connection
require_once __DIR__ . '/koneksi.php';

// Check if user is logged in
if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit();
}

// Validate session timeout (1 hour)
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

// Sanitize username
$username = filter_var(trim($_SESSION['username']), FILTER_SANITIZE_STRING);
if (empty($username) || strlen($username) > 50) {
    session_unset();
    session_destroy();
    header('Location: login.php?error=invalid_session');
    exit();
}

// Ambil data instansi dari database
$query_instansi = "SELECT nama_instansi, logo FROM setting LIMIT 1";
$result_instansi = mysqli_query($koneksi, $query_instansi);
$nama_instansi = "RSUD PRINGSEWU";
$logo_src = "images/logo.png";

if ($result_instansi && $row_instansi = mysqli_fetch_assoc($result_instansi)) {
    if (!empty($row_instansi['nama_instansi'])) {
        $nama_instansi = $row_instansi['nama_instansi'];
    }
    if (!empty($row_instansi['logo'])) {
        $logo_blob = $row_instansi['logo'];
        $logo_base64 = base64_encode($logo_blob);
        $logo_src = "data:image/png;base64," . $logo_base64;
    }
}

// Ambil nama pegawai berdasarkan username (NIK) yang login
$nama_pegawai = $username;
$query_pegawai = "SELECT nama FROM pegawai WHERE nik = ? LIMIT 1";
$stmt_pegawai = mysqli_prepare($koneksi, $query_pegawai);
if ($stmt_pegawai) {
    mysqli_stmt_bind_param($stmt_pegawai, "s", $username);
    mysqli_stmt_execute($stmt_pegawai);
    $result_pegawai = mysqli_stmt_get_result($stmt_pegawai);
    if ($row_pegawai = mysqli_fetch_assoc($result_pegawai)) {
        $nama_pegawai = $row_pegawai['nama'];
    }
    mysqli_stmt_close($stmt_pegawai);
}

// Ambil kd_dokter berdasarkan username yang login
$kd_dokter = null;
$nm_dokter_login = '';
$query_dokter = "SELECT kd_dokter, nm_dokter FROM dokter WHERE kd_dokter = ? LIMIT 1";
$stmt_dokter = mysqli_prepare($koneksi, $query_dokter);
if ($stmt_dokter) {
    mysqli_stmt_bind_param($stmt_dokter, "s", $username);
    mysqli_stmt_execute($stmt_dokter);
    $result_dokter = mysqli_stmt_get_result($stmt_dokter);
    if ($row_dokter = mysqli_fetch_assoc($result_dokter)) {
        $kd_dokter = $row_dokter['kd_dokter'];
        $nm_dokter_login = $row_dokter['nm_dokter'];
    } else {
        $kd_dokter = preg_match('/^[A-Za-z0-9_-]+$/', $username) ? $username : null;
    }
    mysqli_stmt_close($stmt_dokter);
} else {
    $kd_dokter = preg_match('/^[A-Za-z0-9_-]+$/', $username) ? $username : null;
}

// Cek apakah user adalah super admin
$is_super_admin = ($username == '198509172005011001');
