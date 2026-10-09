<?php
// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Check if session is already started
if (session_status() == PHP_SESSION_NONE) {
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

// Rate limiting check
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
                $error = 'Username atau password salah. Silakan coba lagi.';
                break;
            case 'too_many_attempts':
                $error = 'Terlalu banyak percobaan login gagal. Silakan tunggu 5 menit.';
                break;
            case 'invalid_token':
                $error = 'Sesi keamanan tidak valid. Silakan muat ulang halaman.';
                break;
            case 'timeout':
                $error = 'Sesi Anda telah berakhir karena tidak aktif. Silakan login kembali.';
                break;
        }
    }
}

include 'koneksi.php';
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

$attempts_left = $max_attempts - count($_SESSION['login_attempts']);
$is_locked = count($_SESSION['login_attempts']) >= $max_attempts;
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline';">
    <title>Login - <?php echo htmlspecialchars($nama_instansi); ?></title>
    <style>
        :root {
            --primary: #0284c7;
            --primary-dark: #0369a1;
            --primary-light: #e0f2fe;
            --dark: #0f172a;
            --gray: #64748b;
            --light-border: #cbd5e1;
            --radius-lg: 20px;
            --radius-md: 12px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(145deg, #0284c7 0%, #0369a1 50%, #075985 100%);
            color: var(--dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
            line-height: 1.5;
        }

        .login-wrapper {
            width: 100%;
            max-width: 400px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        /* Branding Header */
        .brand-header {
            text-align: center;
            margin-bottom: 24px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .logo-wrap {
            width: 76px;
            height: 84px;
            background: rgba(255, 255, 255, 0.95);
            padding: 8px;
            border-radius: 18px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.18);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 12px;
        }

        .logo-wrap img {
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
        }

        .brand-title {
            font-size: 20px;
            font-weight: 800;
            color: white;
            letter-spacing: 0.5px;
            text-shadow: 0 2px 6px rgba(0, 0, 0, 0.25);
            line-height: 1.2;
        }

        .brand-subtitle {
            font-size: 12px;
            font-weight: 600;
            color: rgba(255, 255, 255, 0.9);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }

        /* Login Card */
        .login-card {
            width: 100%;
            background: white;
            border-radius: var(--radius-lg);
            padding: 28px 24px;
            box-shadow: 0 16px 36px rgba(0, 0, 0, 0.2);
            position: relative;
        }

        .card-header {
            text-align: center;
            margin-bottom: 22px;
        }

        .card-title {
            font-size: 19px;
            font-weight: 800;
            color: #0f172a;
            margin-bottom: 6px;
        }

        .card-subtitle {
            font-size: 13px;
            color: var(--gray);
            line-height: 1.4;
        }

        /* Form Elements */
        .form-group {
            margin-bottom: 16px;
            position: relative;
        }

        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 700;
            color: #334155;
            margin-bottom: 6px;
        }

        .input-group {
            position: relative;
            display: flex;
            align-items: center;
        }

        .input-icon {
            position: absolute;
            left: 14px;
            color: #94a3b8;
            pointer-events: none;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .input-control {
            width: 100%;
            height: 48px;
            padding: 10px 14px 10px 44px;
            border: 1.5px solid var(--light-border);
            border-radius: var(--radius-md);
            font-size: 16px; /* 16px prevents iOS safari zoom on focus */
            color: #0f172a;
            background: #f8fafc;
            outline: none;
            transition: all 0.2s ease;
            -webkit-appearance: none;
        }

        .input-control:focus {
            background: white;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.2);
        }

        .input-control::placeholder {
            color: #94a3b8;
            font-size: 14px;
        }

        /* Show/Hide Password Button */
        .btn-toggle-pwd {
            position: absolute;
            right: 8px;
            background: none;
            border: none;
            color: #64748b;
            padding: 8px 10px;
            cursor: pointer;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            transition: color 0.2s;
        }
        .btn-toggle-pwd:hover, .btn-toggle-pwd:active {
            color: var(--primary);
        }

        /* Submit Button */
        .btn-submit {
            width: 100%;
            height: 50px;
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: white;
            border: none;
            border-radius: var(--radius-md);
            font-size: 16px;
            font-weight: 700;
            letter-spacing: 0.3px;
            cursor: pointer;
            margin-top: 8px;
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.35);
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-submit:hover {
            opacity: 0.95;
            box-shadow: 0 6px 16px rgba(2, 132, 199, 0.45);
        }

        .btn-submit:active {
            transform: scale(0.98);
        }

        /* Alerts */
        .alert {
            padding: 12px 14px;
            border-radius: 10px;
            font-size: 13px;
            margin-bottom: 18px;
            display: flex;
            align-items: flex-start;
            gap: 10px;
            line-height: 1.4;
        }

        .alert-error {
            background-color: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }

        .alert-warning {
            background-color: #fffbeb;
            color: #92400e;
            border: 1px solid #fef3c7;
        }

        /* Footer */
        .brand-footer {
            margin-top: 24px;
            font-size: 12px;
            color: rgba(255, 255, 255, 0.8);
            text-align: center;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
        }

        @media (max-width: 480px) {
            body {
                padding: 18px 14px;
                justify-content: flex-start;
            }
            .brand-header {
                margin-top: 8px;
                margin-bottom: 18px;
            }
            .login-card {
                padding: 22px 18px;
            }
            .card-title {
                font-size: 18px;
            }
        }
    </style>
</head>
<body>

<div class="login-wrapper">
    <!-- Header Logo & Instansi -->
    <div class="brand-header">
        <div class="logo-wrap">
            <img src="<?php echo htmlspecialchars($logo_src); ?>" alt="Logo <?php echo htmlspecialchars($nama_instansi); ?>">
        </div>
        <div class="brand-title"><?php echo htmlspecialchars($nama_instansi); ?></div>
        <div class="brand-subtitle">Sistem Pelayanan Dokter</div>
    </div>

    <!-- Login Card -->
    <div class="login-card">
        <div class="card-header">
            <div class="card-title">Masuk ke Sistem</div>
            <div class="card-subtitle">Gunakan User (NIK) dan Password SIMRS Khanza Anda</div>
        </div>

        <?php if (!empty($error)): ?>
            <div class="alert alert-error">
                <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span><?php echo htmlspecialchars($error); ?></span>
            </div>
        <?php endif; ?>

        <?php if ($attempts_left < 3 && !$is_locked): ?>
            <div class="alert alert-warning">
                <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24" style="flex-shrink:0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>Perhatian: Tersisa <strong><?php echo $attempts_left; ?></strong> kesempatan percobaan login.</span>
            </div>
        <?php endif; ?>

        <?php if ($is_locked): ?>
            <div class="alert alert-error" style="flex-direction:column; align-items:center; text-align:center;">
                <svg width="32" height="32" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                <strong style="margin-top:6px; font-size:14px;">Akun Terkunci Sementara</strong>
                <span style="font-size:12px; margin-top:4px;">Terlalu banyak percobaan gagal. Silakan coba kembali dalam <?php echo ceil($lockout_time/60); ?> menit.</span>
            </div>
        <?php else: ?>
            <form method="POST" action="login.php" id="loginForm" onsubmit="handleLoginSubmit(event)">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="login" value="1">

                <!-- Field Username -->
                <div class="form-group">
                    <label class="form-label" for="username">Username / NIK</label>
                    <div class="input-group">
                        <span class="input-icon">
                            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        </span>
                        <input 
                            type="text" 
                            id="username" 
                            name="username" 
                            class="input-control" 
                            placeholder="Masukkan NIK atau User ID" 
                            required 
                            maxlength="50" 
                            autocomplete="username" 
                            autocapitalize="none"
                            autocorrect="off"
                            spellcheck="false"
                        >
                    </div>
                </div>

                <!-- Field Password -->
                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <div class="input-group">
                        <span class="input-icon">
                            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        </span>
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            class="input-control" 
                            placeholder="Masukkan Password" 
                            required 
                            maxlength="100" 
                            autocomplete="current-password"
                            style="padding-right: 44px;"
                        >
                        <button type="button" class="btn-toggle-pwd" id="btnTogglePwd" onclick="togglePasswordVisibility()" title="Lihat password" aria-label="Lihat password">
                            <svg id="eyeIcon" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        </button>
                    </div>
                </div>

                <!-- Submit Button -->
                <button type="submit" name="login" class="btn-submit" id="btnLogin">
                    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                    <span>Masuk</span>
                </button>
            </form>
        <?php endif; ?>
    </div>

    <!-- Footer -->
    <div class="brand-footer">
        &copy; <?php echo date('Y'); ?> IT <?php echo htmlspecialchars($nama_instansi); ?>
    </div>
</div>

<script>
    function togglePasswordVisibility() {
        const pwdInput = document.getElementById('password');
        const eyeIcon = document.getElementById('eyeIcon');
        if (!pwdInput || !eyeIcon) return;

        if (pwdInput.type === 'password') {
            pwdInput.type = 'text';
            eyeIcon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
        } else {
            pwdInput.type = 'password';
            eyeIcon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
        }
    }

    function handleLoginSubmit(e) {
        const btn = document.getElementById('btnLogin');
        if (btn) {
            setTimeout(function() {
                btn.disabled = true;
                btn.style.opacity = '0.7';
                btn.innerHTML = '<span>Memverifikasi...</span>';
            }, 10);
        }
    }
</script>

</body>
</html>
