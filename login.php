<?php
// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Configure secure session settings before starting session
if (session_status() == PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
}
session_start();

// Set timezone Indonesia (Jakarta)
date_default_timezone_set('Asia/Jakarta');

include 'koneksi.php';

// Redirect if already logged in
if (isset($_SESSION['username']) && !empty($_SESSION['username'])) {
    header('Location: index.php');
    exit();
}

$error = '';

// Rate limiting setup
$max_attempts = 5;
$lockout_time = 300; // 5 minutes
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// Initialize login attempts tracking
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

// Clean old attempts (older than lockout time)
$current_time = time();
$_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'], function($attempt_time) use ($current_time, $lockout_time) {
    return ($current_time - $attempt_time) < $lockout_time;
});

// Process login form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    
    error_log("Login attempt started for POST data: " . print_r($_POST, true));
    
    // Check rate limiting first
    if (count($_SESSION['login_attempts']) >= $max_attempts) {
        error_log("Rate limit exceeded for IP: " . $ip);
        header('Location: login_view.php?error=too_many_attempts');
        exit();
    }
    
    // CSRF Token validation
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || 
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        error_log("CSRF token mismatch for IP: " . $ip);
        header('Location: login_view.php?error=invalid_token');
        exit();
    }
    
    // Input validation and sanitization - simplified for debugging
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $_SESSION['login_attempts'][] = $current_time;
        error_log("Empty username or password. Username: '$username', Password length: " . strlen($password));
        header('Location: login_view.php?error=invalid_credentials');
        exit();
    }
    
    // Length validation
    if (strlen($username) > 50 || strlen($password) > 100) {
        $_SESSION['login_attempts'][] = $current_time;
        error_log("Input length validation failed for user: " . $username . " IP: " . $ip);
        header('Location: login_view.php?error=invalid_credentials');
        exit();
    }
    
    // Character validation for username - relaxed for debugging
    /*
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
        $_SESSION['login_attempts'][] = $current_time;
        error_log("Username contains invalid characters: " . $username . " IP: " . $ip);
        header('Location: login_view.php?error=invalid_credentials');
        exit();
    }
    */

    try {
        // Prepared statement with error handling
        $stmt = mysqli_prepare($koneksi, "SELECT id_user, password FROM user WHERE aes_decrypt(id_user, 'nur') = ? LIMIT 1");
        
        if ($stmt === false) {
            error_log("Database prepare failed: " . mysqli_error($koneksi));
            $_SESSION['login_attempts'][] = $current_time;
            header('Location: login_view.php?error=invalid_credentials');
            exit();
        }
        
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($user = mysqli_fetch_assoc($result)) {
            // Debug: Log user found
            error_log("User found in database: " . $username);
            
            // Use original query method that was working
            $stmt_check = mysqli_prepare($koneksi, "SELECT id_user FROM user WHERE aes_decrypt(id_user, 'nur') = ? AND aes_decrypt(password, 'windi') = ? LIMIT 1");
            mysqli_stmt_bind_param($stmt_check, "ss", $username, $password);
            mysqli_stmt_execute($stmt_check);
            $check_result = mysqli_stmt_get_result($stmt_check);
            
            if (mysqli_fetch_assoc($check_result)) {
                // Successful login
                session_regenerate_id(true); // Prevent session fixation
                
                $_SESSION['username'] = $username;
                $_SESSION['status'] = "login";
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();
                $_SESSION['regenerated'] = true;
                
                // Clear login attempts on successful login
                unset($_SESSION['login_attempts']);
                
                // Log successful login
                error_log("Successful login for user: " . $username . " IP: " . $ip);
                
                header("Location: index.php");
                exit();
            } else {
                // Invalid password
                $_SESSION['login_attempts'][] = $current_time;
                error_log("Password verification failed for user: " . $username . " IP: " . $ip);
                header('Location: login_view.php?error=invalid_credentials');
                exit();
            }
            
            mysqli_stmt_close($stmt_check);
        } else {
            // User not found
            $_SESSION['login_attempts'][] = $current_time;
            error_log("User not found: " . $username . " IP: " . $ip);
            header('Location: login_view.php?error=invalid_credentials');
            exit();
        }
        
        mysqli_stmt_close($stmt);
        
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage() . " IP: " . $ip);
        $_SESSION['login_attempts'][] = $current_time;
        header('Location: login_view.php?error=invalid_credentials');
        exit();
    }
}

include 'login_view.php'; // tampilkan tampilan login
?>
