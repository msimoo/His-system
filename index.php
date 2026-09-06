<?php
ob_start();
include __DIR__ . "/session_init.php";
include_once('pos/admin/config/config.php');
include('pos/admin/config/languages.php');

$err = '';
$redirect = '';

function verifyPassword($input, $storedHash) {
    if (password_verify($input, $storedHash)) {
        return true;
    }
    $legacyHash = sha1(md5($input));
    if (hash_equals($legacyHash, $storedHash)) {
        return true;
    }
    return false;
}

function upgradePasswordHash($mysqli, $table, $idColumn, $idValue, $newHash) {
    $stmt = $mysqli->prepare("UPDATE $table SET admin_password = ? WHERE $idColumn = ?");
    $stmt->bind_param('ss', $newHash, $idValue);
    $stmt->execute();
    $stmt->close();
}

if (isset($_POST['login'])) {
    if (!validateCsrf($_POST['csrf_token'] ?? '')) {
        $err = 'Invalid CSRF token';
    } else {
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            $err = 'Email and password are required';
        } else {
            $redirect = '';

            // Try admin login first
            $stmt = $mysqli->prepare("SELECT admin_id, admin_role, admin_password, admin_name FROM rpos_admin WHERE admin_email = ? LIMIT 1");
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $stmt->bind_result($admin_id, $admin_role, $storedHash, $admin_name);
            $rs = $stmt->fetch();
            $stmt->close();

            if ($rs && verifyPassword($password, $storedHash)) {
                session_regenerate_id(true);
                $_SESSION['admin_id'] = $admin_id;
                $_SESSION['admin_role'] = $admin_role;
                $_SESSION['admin_name'] = $admin_name;
                
                if ($storedHash !== password_hash($password, PASSWORD_DEFAULT)) {
                    $newHash = password_hash($password, PASSWORD_DEFAULT);
                    upgradePasswordHash($mysqli, 'rpos_admin', 'admin_id', $admin_id, $newHash);
                }
                
                $redirect = 'pos/admin/dashboard.php';
            } else {
                // Try staff login
                $stmt = $mysqli->prepare("SELECT s.staff_id, r.role_name, s.staff_password, s.staff_name
                    FROM rpos_staff s
                    LEFT JOIN rpos_roles r ON s.staff_role_id = r.role_id
                    WHERE s.staff_email = ? AND s.staff_status = 'Active' LIMIT 1");
                $stmt->bind_param('s', $email);
                $stmt->execute();
                $stmt->bind_result($staff_id, $staff_role_name, $storedHash, $staff_name);
                $rs2 = $stmt->fetch();
                $stmt->close();

                if ($rs2 && verifyPassword($password, $storedHash)) {
                    session_regenerate_id(true);
                    $_SESSION['staff_id'] = $staff_id;
                    $_SESSION['admin_id'] = $staff_id;
                    $_SESSION['admin_role'] = strtolower($staff_role_name);
                    $_SESSION['admin_name'] = $staff_name;

                    if ($storedHash !== password_hash($password, PASSWORD_DEFAULT)) {
                        $newHash = password_hash($password, PASSWORD_DEFAULT);
                        upgradePasswordHash($mysqli, 'rpos_staff', 'staff_id', $staff_id, $newHash);
                    }

                    // Redirect based on role
                    $role = strtolower($staff_role_name);
                    if ($role === 'pos') {
                        $redirect = 'pos/cashier/dashboard.php';
                    } elseif ($role === 'accountant') {
                        $redirect = 'pos/account/dashboard.php';
                    } else {
                        $redirect = 'pos/admin/dashboard.php';
                    }
                } else {
                    $err = 'Incorrect credentials';
                }
            }
        }
    }
}

$csrfToken = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>HIS Management System - Login</title>

    <link href="pos/admin/assets/vendor/@fortawesome/fontawesome-free/css/all.min.css" rel="stylesheet">
    <!-- Fonts -->
     <!-- Styles -->
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html,body { height: 100%; }
        body {
            font-family: 'Tajawal', Poppins, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;
            background: radial-gradient(1200px 600px at 10% 10%, rgba(255,255,255,0.04), transparent),
                        radial-gradient(1000px 500px at 90% 90%, rgba(255,255,255,0.03), transparent),
                        linear-gradient(135deg,#3b8dff 0%, #6c63ff 50%, #b86bff 100%);
            display: flex; align-items: center; justify-content: center; padding: 40px;
            -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
        }

        .login-card {
            width: 100%; max-width: 920px; display: grid; grid-template-columns: 1fr 420px; gap: 30px;
            align-items: center;
        }

        .panel-illustration {
            border-radius: 18px; padding: 40px; color: #fff; position: relative;
            background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
            box-shadow: 0 10px 30px rgba(0,0,0,0.15), inset 0 1px 0 rgba(255,255,255,0.03);
            min-height: 340px; display: flex; flex-direction: column; justify-content: center;
        }

        .panel-illustration h2 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
        .panel-illustration p { opacity: 0.9; font-size: 15px; line-height: 1.45; }

        .login-container {
            background: rgba(255,255,255,0.98); border-radius: 18px; padding: 36px; position: relative;
            box-shadow: 0 20px 40px rgba(12,24,48,0.18);
        }

        .brand {
            display:flex; align-items:center; gap:12px; margin-bottom:18px;
        }

        .brand .mark { width:56px; height:56px; background:linear-gradient(135deg,#6c63ff,#3b8dff); border-radius:12px; display:flex; align-items:center; justify-content:center; color:#fff; font-weight:700; font-size:20px; box-shadow:0 6px 18px rgba(99,102,241,0.28); }

        .brand h1 { font-size:20px; font-weight:700; color:#222; }
        .brand p { font-size:13px; color:#666; margin-top:2px; }

        .form-group { position:relative; margin-bottom:18px; }
        .form-group i { position:absolute; left:14px; top:50%; transform:translateY(-50%); color:#8993a4; font-size:16px; }
        .form-group input { width:100%; padding:14px 18px 14px 48px; border-radius:12px; border:1px solid #e6eef8; background:#fbfdff; font-size:15px; transition:all .18s ease; }
        .form-group select { width:100%; padding:14px 18px 14px 48px; border-radius:12px; border:1px solid #e6eef8; color:#e6eef8; background:#6e52ff; font-size:15px; transition:all .18s ease; }
        .form-group select:hover {border:1px solid #0e0e10; color:#e6eef8; background:#070707; font-size:15px; transition:all .18s ease; }
        .form-group select:focus { outline:none; box-shadow:0 6px 18px rgba(59,141,255,0.12); border-color:#77a9ff; }
        .form-group input:focus { outline:none; box-shadow:0 6px 18px rgba(59,141,255,0.12); border-color:#77a9ff; }

        .actions { display:flex; gap:12px; align-items:center; margin-top:6px; }
        .login-btn { flex:1; padding:12px 16px; background:linear-gradient(90deg,#5262ff,#7b4bff); color:#fff; border:none; border-radius:10px; font-weight:600; cursor:pointer; box-shadow:0 8px 24px rgba(91,80,255,0.18); transition:transform .14s ease, box-shadow .14s ease; }
        .login-btn:hover { transform:translateY(-3px); box-shadow:0 18px 36px rgba(91,80,255,0.22); }

        .meta { display:flex; align-items:center; gap:10px; font-size:13px; color:#6b7280; }
        .meta input[type=checkbox] { width:16px; height:16px; }

        .error { background:#fff0f0; color:#b72121; padding:10px; border-radius:8px; margin-bottom:14px; border-left:4px solid #f66; }

        @media (max-width:920px) { .login-card { grid-template-columns: 1fr; max-width:420px; } .panel-illustration{order:2} }
    </style>
    <!-- Font Awesome for icons -->
   </head>

<body>

 
    <div class="particles">
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
    </div>
 

    <div class="login-card">
        <div class="panel-illustration">
            
            <h2 class="text-white font-weight-bold mb-0"><?php echo $current_lang === 'ar' ? 'مرحباً بكم في مركز الواحات الطبي' : 'Welcome to Al-Wahat Medical Center'; ?></h2>
            <p><?php echo $current_lang === 'ar' ? 'نظام إدارة المراكز الطبية — سجّل دخولك للوصول إلى لوحة التحكم المناسبة لدورك.' : 'Medical Center Management System — Sign in to access your dashboard.'; ?></p>
            <p>Developed By M.Omer Elsamani <i class="fas fa-spinner fa-spin"></i></p>
        </div>

        <div class="login-container" <?php echo $current_lang === 'ar' ? 'dir="rtl"' : ''; ?>>
            <div class="brand">
                <div class="mark">م</div>
                <div>
                    <h1>مركز الواحات الطبي</h1>
                    <p><?php echo $current_lang === 'ar' ? 'نظام إدارة' : 'Management System'; ?></p>
                </div>
            </div>

            <?php if (!empty($err)): ?>
                <div class="error">
                    <i class="fas fa-exclamation-triangle"></i> <?php echo $err; ?>
                </div>
            <?php endif; ?>

            <form method="post">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                <div class="form-group">
                    <i class="fas fa-envelope"></i>
                    <select name="email" class="form-group input" required>
    <option value="" disabled selected>--</option>
    <?php
    $c_res = $mysqli->query("SELECT admin_id, admin_name, admin_email FROM rpos_admin ORDER BY admin_name ASC");
    while($c = $c_res->fetch_object()){ echo "<option value='{$c->admin_email}'>{$c->admin_email}</option>"; }
                    ?>
                    </select>
                    <!--<input type="email" name="email" placeholder="<?php echo $current_lang === 'ar' ? 'البريد الإلكتروني' : 'Email Address'; ?>" required>-->
                </div>
                <div class="form-group">
                    <i class="fas fa-lock"></i>
                    <input type="password" name="password" placeholder="<?php echo $current_lang === 'ar' ? 'كلمة المرور' : 'Password'; ?>" required>
                </div>

                <div class="actions">
                    <!--<div class="meta">
                        <input type="checkbox" id="remember" name="remember">
                        <label for="remember"><?php echo $current_lang === 'ar' ? 'تذكرني' : 'Remember me'; ?></label>
                    </div>-->
                    <button type="submit" name="login" class="login-btn">
                        <i class="fas fa-sign-in-alt"></i> <?php echo $current_lang === 'ar' ? 'تسجيل الدخول' : 'Sign In'; ?>
                    </button>
                </div>
            </form>

        </div>
    </div>

    <script>
        // Add some interactive effects
        document.querySelectorAll('.form-group input').forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'scale(1.02)';
            });
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'scale(1)';
            });
        });
        <?php if (!empty($redirect)): ?>
        window.location.href = '<?php echo $redirect; ?>';
        <?php endif; ?>
    </script>
</body>

</html>