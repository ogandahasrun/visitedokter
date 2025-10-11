<?php
// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Check if session is already started
if (session_status() == PHP_SESSION_NONE) {
    // Configure session only if not started yet
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    session_start();
}

// Set timezone Indonesia (Jakarta)
date_default_timezone_set('Asia/Jakarta');

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting check (simple implementation)
$max_attempts = 5;
$lockout_time = 300; // 5 minutes
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

// Clean old attempts
$current_time = time();
$_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'], function($attempt_time) use ($current_time, $lockout_time) {
    return ($current_time - $attempt_time) < $lockout_time;
});

$error = '';
if (isset($_GET['error'])) {
    $allowed_errors = ['invalid_credentials', 'too_many_attempts', 'invalid_token', 'timeout'];
    $error_type = filter_var($_GET['error'], FILTER_SANITIZE_STRING);
    
    if (in_array($error_type, $allowed_errors)) {
        switch ($error_type) {
            case 'invalid_credentials':
                $error = 'Username atau password salah.';
                break;
            case 'too_many_attempts':
                $error = 'Terlalu banyak percobaan login. Coba lagi dalam 5 menit.';
                break;
            case 'invalid_token':
                $error = 'Sesi tidak valid. Silakan coba lagi.';
                break;
            case 'timeout':
                $error = 'Sesi telah berakhir. Silakan login kembali.';
                break;
        }
    }
}

include 'koneksi.php';
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
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self';">
    <title>Login <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        body {
            background: linear-gradient(to right, #00c6ff, #0072ff);
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
        }
        .login-container {
            width: 350px;
            margin: 100px auto;
            padding: 30px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
        }
        h2 {
            text-align: center;
            margin-bottom: 20px;
            color: #333;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            margin: 10px 0;
            padding: 12px;
            border-radius: 5px;
            border: 1px solid #ccc;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #007bff;
            border: none;
            color: white;
            font-size: 16px;
            margin-top: 10px;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background: #0056b3;
        }
        .error {
            background: #ffdddd;
            border: 1px solid #ff5c5c;
            padding: 10px;
            margin-bottom: 15px;
            color: #d8000c;
            border-radius: 5px;
            text-align: center;
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
        .login-container form {
            margin: 0;
        }
        .login-container input:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 5px rgba(0,123,255,0.3);
        }
        .rate-limit-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 5px;
            text-align: center;
        }
    </style>
</head>
<body>

<div class="logo-container">
    <img src="<?php echo htmlspecialchars($logo_src); ?>" alt="Logo <?php echo htmlspecialchars($nama_instansi); ?>" width="100" height="120">
    <div class="instansi-name"><?php echo htmlspecialchars($nama_instansi); ?></div>
</div>

<div class="login-container">
    <h2>Silahkan Masukkan User dan Password Aplikasi Simkes Khanza Anda</h2>
    
    <?php if (!empty($error)): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    
    <?php if (count($_SESSION['login_attempts']) >= ($max_attempts - 2) && count($_SESSION['login_attempts']) < $max_attempts): ?>
        <div class="rate-limit-warning">
            Peringatan: Anda memiliki <?php echo ($max_attempts - count($_SESSION['login_attempts'])); ?> percobaan login tersisa.
        </div>
    <?php endif; ?>
    
    <?php if (count($_SESSION['login_attempts']) >= $max_attempts): ?>
        <div class="error">
            Akun Anda telah dikunci karena terlalu banyak percobaan login yang gagal. 
            Silakan coba lagi dalam <?php echo ceil($lockout_time/60); ?> menit.
        </div>
    <?php else: ?>
        <form method="post" action="login.php">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="text" name="username" placeholder="Username" required maxlength="50" autocomplete="username">
            <input type="password" name="password" placeholder="Password" required maxlength="100" autocomplete="current-password">
            <button type="submit" name="login">Login</button>
        </form>
    <?php endif; ?>
</div>

</body>
</html>
