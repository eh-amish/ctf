#!/usr/bin/env bash
# setup_infector_web.sh
# Run as root on Ubuntu Server. Creates Infector.htb and admin.Infector.htb sites + CTF endpoints.
set -euo pipefail
IFS=$'\n\t'

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

# Variables
WEB_ROOT="/var/www"
SITE="Infector.htb"
SITE_ROOT="$WEB_ROOT/$SITE/public_html"
ADMIN_SITE="admin.Infector.htb"
ADMIN_ROOT="$WEB_ROOT/$ADMIN_SITE/public_html"
DATA_DIR="$SITE_ROOT/data"
ADMIN_UPLOADS="$ADMIN_ROOT/uploads"
APACHE_SITES_DIR="/etc/apache2/sites-available"
ADMIN_TOKEN_FILE="$DATA_DIR/admin_token.txt"
CREDS_FILE="$DATA_DIR/creds.json"
USERS_FILE="$DATA_DIR/users.json"

# Ensure Apache & PHP installed
apt update
apt -y install apache2 php php-cli php-mbstring php-xml php-curl ufw openssl --no-install-recommends

# Create directory structure
mkdir -p "$SITE_ROOT" "$ADMIN_ROOT" "$DATA_DIR" "$ADMIN_UPLOADS"

# Create /etc/hosts entries (local)
if ! grep -q "$SITE" /etc/hosts 2>/dev/null; then
  echo "127.0.0.1 $SITE $ADMIN_SITE" >> /etc/hosts
  echo "Added 127.0.0.1 $SITE and $ADMIN_SITE to /etc/hosts"
fi

# Basic no-history for interactive shells (optional)
cat > /etc/profile.d/no_history.sh <<'SH'
#!/bin/sh
export HISTFILE=/dev/null
SH
chmod 644 /etc/profile.d/no_history.sh

# Create admin token (persistent)
if [ ! -f "$ADMIN_TOKEN_FILE" ]; then
  mkdir -p "$DATA_DIR"
  ADMIN_TOKEN=$(openssl rand -hex 16)
  echo "$ADMIN_TOKEN" > "$ADMIN_TOKEN_FILE"
  chown www-data:www-data "$ADMIN_TOKEN_FILE"
  chmod 640 "$ADMIN_TOKEN_FILE"
else
  ADMIN_TOKEN=$(cat "$ADMIN_TOKEN_FILE")
fi

# Create hidden creds.json (password stored as MD5 of 'rockmyworld')
MD5_PASS=$(echo -n "rockmyworld" | md5sum | awk '{print $1}')
cat > "$CREDS_FILE" <<EOF
{
  "username": "nspire",
  "role": "admin",
  "password": "$MD5_PASS"
}
EOF
chown www-data:www-data "$CREDS_FILE"
chmod 640 "$CREDS_FILE"

# Create a sample users.json if not exists (pre-hashed passwords)
if [ ! -f "$USERS_FILE" ]; then
  cat > "$USERS_FILE" <<'JSON'
[
  {"id":"1","username":"alex","email":"alex@Infector.htb","password":"$2y$10$kL6KOvQWBq5mMpjI9gHn..s4wnstZrPTcmmH1fukVtqG6R6U1T.ZG"},
  {"id":"2","username":"admin","email":"admin@Infector.htb","password":"$2y$10$vSd5PUe8vF5.q/x5rhT3BO0EcdOPGZClEv9gOdLgF6q2x/Nk7JHL2"}
]
JSON
  chown www-data:www-data "$USERS_FILE"
  chmod 640 "$USERS_FILE"
fi

# Write index.html (login page) into SITE_ROOT
cat > "$SITE_ROOT/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Infector — Login</title>
    <link rel="stylesheet" type="text/css" href="./assets/style.css" />
  </head>
  <body>
    <div class="container">
      <div class="login-box">
        <h2>Login</h2>
        <form id="loginForm" method="post" action="/login.php" autocomplete="off">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" placeholder="Enter username" autocomplete="username" />
          <span id="usernameError" class="error-message" style="display: none">Username is required</span>

          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="Enter password" autocomplete="current-password" />
          <span id="passwordError" class="error-message" style="display: none">Password is required</span>

          <input type="hidden" id="role" name="role" value="user" />
          <button type="submit" id="submitBtn">Login</button>

          <div class="meta-row">
            <span class="cta">Don't have an account yet? <a href="./register.html">Register here</a></span>
            <span class="admin-hint">Admin panel available on <strong>admin.Infector.htb</strong></span>
          </div>
        </form>
      </div>
    </div>
    <script src="./assets/main.js"></script>
  </body>
</html>
HTML

# register.html
cat > "$SITE_ROOT/register.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
  <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Register</title><link rel="stylesheet" href="./assets/style.css"></head>
  <body>
    <div class="container">
      <div class="register-box">
        <h2>Create an account</h2>
        <form id="registerForm" method="post" action="/register.php" autocomplete="off">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email"/>
          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="Choose a password" required autocomplete="new-password"/>
          <button type="submit">Register</button>
          <span class="cta">Already have an account? <a href="./index.html">Login here</a></span>
        </form>
      </div>
    </div>
  </body>
</html>
HTML

# assets directory + CSS
mkdir -p "$SITE_ROOT/assets"
cat > "$SITE_ROOT/assets/style.css" <<'CSS'
/* Infector theme - lightweight */
* { box-sizing: border-box; }
html,body{height:100%;margin:0;font-family: "Poppins", sans-serif;background:#0b1220;color:#e6eef8;}
body::before{content:"";position:fixed;inset:0;background-image:url('./assets/background.jpg');background-size:cover;background-position:center;filter:blur(3px) brightness(0.55) saturate(0.9);z-index:-2}
body::after{content:"";position:fixed;inset:0;background:linear-gradient(180deg, rgba(6,8,15,0.45), rgba(6,8,15,0.75));z-index:-1}
.container{display:flex;justify-content:center;align-items:center;padding:32px;min-height:100vh}
.login-box,.register-box{width:100%;max-width:420px;background:rgba(255,255,255,0.03);padding:28px;border-radius:8px;box-shadow:0 8px 30px rgba(2,6,23,0.6);backdrop-filter:blur(6px)}
h2{margin-top:0;margin-bottom:14px;font-size:1.4rem;letter-spacing:0.2px}
form{display:flex;flex-direction:column;gap:10px}
label{color:#b9c5d3;font-size:0.95rem;margin-bottom:6px}
input[type="text"],input[type="email"],input[type="password"]{padding:10px 12px;font-size:1rem;border:1px solid rgba(255,255,255,0.06);background:rgba(255,255,255,0.02);color:#e6eef8;border-radius:6px;outline:none}
input:focus{border-color:rgba(255,90,95,0.9);box-shadow:0 4px 14px rgba(255,90,95,0.06)}
.error-message{color:#ff8b8b;font-size:0.9rem;margin-top:-6px}
button[type="submit"]{margin-top:6px;padding:12px;background:linear-gradient(90deg,#ff5a5f,#ff7a7f);color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;font-size:1rem}
.meta-row{display:flex;justify-content:space-between;align-items:center;margin-top:12px;gap:8px;font-size:0.95rem}
.cta a{color:#ffd1d3;text-decoration:none;margin-left:6px}
.admin-hint{color:#b8c2cc;font-size:0.85rem;text-align:right}
@media (max-width:600px){.login-box,.register-box{padding:18px;margin:14px}}
CSS

# small client validation JS
cat > "$SITE_ROOT/assets/main.js" <<'JS'
document.addEventListener('DOMContentLoaded', function () {
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', function (ev) {
      const u = document.getElementById('username');
      const p = document.getElementById('password');
      const ue = document.getElementById('usernameError');
      const pe = document.getElementById('passwordError');
      let ok = true;
      if (!u || u.value.trim() === '') { ue.style.display='block'; ok=false; } else ue.style.display='none';
      if (!p || p.value.trim() === '') { pe.style.display='block'; ok=false; } else pe.style.display='none';
      if (!ok) ev.preventDefault();
    }, false);
  }
});
JS

# create a tiny placeholder background image (1x1 PNG colored) from base64
cat > "$SITE_ROOT/assets/background.jpg" <<'BASE64'
/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAICAgICAgICAgICAgICAgICAwUDAwMDAwYGBQUFBQgHBwcHBwcHBwkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQv/2wCEAQMDAwUFBQkHBwkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQv/wAARCAAQABADASIAAhEBAxEB/8QAFgABAQEAAAAAAAAAAAAAAAAAAAEF/8QAIBAAAgICAgIDAAAAAAAAAAAAAQIDBAAREgUTIUFRcf/EABUBAQEAAAAAAAAAAAAAAAAAAAID/8QAFxEBAQEBAAAAAAAAAAAAAAAAAQARIv/aAAwDAQACEQMRAD8A9K5r1q1r0orq9VWqorq9Qq7q9Qq7q9Qq7q9Qq//9k=
BASE64
# decode base64 to actual file
base64 -d "$SITE_ROOT/assets/background.jpg" > "$SITE_ROOT/assets/background.jpg.tmp" 2>/dev/null || true
# if decode failed, create an empty file fallback
if [ -s "$SITE_ROOT/assets/background.jpg.tmp" ]; then
  mv "$SITE_ROOT/assets/background.jpg.tmp" "$SITE_ROOT/assets/background.jpg"
else
  rm -f "$SITE_ROOT/assets/background.jpg.tmp"
  # create 1x1 png using printf (very small binary) as fallback
  printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\nIDAT\x08\xd7c\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x02\xdb\x00\x00\x00\x00IEND\xaeB`\x82' > "$SITE_ROOT/assets/background.jpg"
fi

# login.php
cat > "$SITE_ROOT/login.php" <<'PHP'
<?php
$data_dir = __DIR__ . '/data';
$users_file = $data_dir . '/users.json';
$admin_token_file = $data_dir . '/admin_token.txt';
if (!is_dir($data_dir)) mkdir($data_dir,0750,true);
if (!file_exists($users_file)) file_put_contents($users_file,json_encode([]));
$users = json_decode(@file_get_contents($users_file), true);
if (!is_array($users)) $users = [];
$response = ['status'=>'failed','message'=>'Invalid credentials'];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'user';
    $ok = false;
    foreach ($users as $u) {
        if (isset($u['username']) && $u['username'] === $username && isset($u['password']) && password_verify($password, $u['password'])) {
            $ok = true; break;
        }
    }
    if ($role === 'admin') {
        if (file_exists($admin_token_file)) { $adm = trim(file_get_contents($admin_token_file)); $response['token'] = $adm; }
        else { $adm = bin2hex(random_bytes(12)); file_put_contents($admin_token_file,$adm); $response['token'] = $adm; }
        $response['status'] = 'failed'; $response['message'] = 'Invalid credentials';
    } elseif ($ok) {
        $response['status']='success'; $response['message']='Login successful'; $response['token']=bin2hex(random_bytes(12));
    } else {
        $response['status']='failed'; $response['message']='Invalid credentials';
    }
    header('Content-Type: application/json'); echo json_encode($response); exit;
}
?>
<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head><body>
<h2>Login endpoint</h2><form method="post"><label>username <input name="username"></label><br>
<label>password <input type="password" name="password"></label><br>
<label>role <input name="role" value="user"></label><br><button type="submit">Submit</button></form>
<p>Note: POSTing role=admin will return the admin token (CTF behavior).</p>
</body></html>
PHP

# register.php
cat > "$SITE_ROOT/register.php" <<'PHP'
<?php
$data_dir = __DIR__.'/data';
$users_file = $data_dir.'/users.json';
if (!is_dir($data_dir)) mkdir($data_dir,0750,true);
if (!file_exists($users_file)) file_put_contents($users_file,json_encode([]));
$users = json_decode(@file_get_contents($users_file), true);
if (!is_array($users)) $users = [];
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    if ($email === '' || $password === '') { $msg = "Email and password are required."; }
    else {
        $parts = explode('@',$email);
        $username = $parts[0] ?? $email;
        $exists = false;
        foreach ($users as $u) { if (($u['email'] ?? '') === $email || ($u['username'] ?? '') === $username) { $exists=true; break; } }
        if ($exists) { $msg = "Account already exists."; }
        else {
            $id = (string)(count($users)+1);
            $users[] = ['id'=>$id,'username'=>$username,'email'=>$email,'password'=>password_hash($password,PASSWORD_DEFAULT)];
            file_put_contents($users_file,json_encode($users,JSON_PRETTY_PRINT));
            @chown($users_file,'www-data');
            $msg = "Registered successfully. You may login.";
        }
    }
}
?>
<!doctype html><html><head><meta charset="utf-8"><title>Register</title></head><body>
<h2>Register</h2><?php if ($msg): ?><p><?=htmlspecialchars($msg)?></p><?php endif; ?>
<form method="post"><label>Email <input type="email" name="email" required></label><br>
<label>Password <input type="password" name="password" required></label><br><button type="submit">Register</button></form>
</body></html>
PHP

# Admin upload page (serves from ADMIN_ROOT/upload.php)
cat > "$ADMIN_ROOT/upload.php" <<'PHP'
<?php
$expected_token_file = '/var/www/Infector.htb/public_html/data/admin_token.txt';
$uploads_dir = __DIR__ . '/uploads';
$expected = '';
if (file_exists($expected_token_file)) { $expected = trim(file_get_contents($expected_token_file)); }
$provided = '';
if (!empty($_SERVER['HTTP_X_AUTH_TOKEN'])) $provided = $_SERVER['HTTP_X_AUTH_TOKEN'];
if (!$provided && isset($_GET['token'])) $provided = $_GET['token'];
if (!$provided && isset($_POST['token'])) $provided = $_POST['token'];
if ($provided !== $expected) { http_response_code(403); echo "Forbidden: valid admin token required."; exit; }
if (!is_dir($uploads_dir)) mkdir($uploads_dir,0755,true);
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = basename($_FILES['file']['name']);
    $dest = $uploads_dir . '/' . $name;
    if (move_uploaded_file($_FILES['file']['tmp_name'],$dest)) echo "Uploaded to /uploads/".htmlspecialchars($name);
    else echo "Upload failed.";
    exit;
}
?>
<!doctype html><html><head><meta charset="utf-8"><title>Admin Upload</title></head><body>
<h2>Admin Upload</h2><form method="post" enctype="multipart/form-data"><input type="file" name="file" required><br><br><button type="submit">Upload</button></form>
<p>Uploaded files will be placed in /uploads/ and are accessible from the admin domain.</p>
</body></html>
PHP

# Create placeholder index for admin site (so admin root works)
cat > "$ADMIN_ROOT/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Admin</title></head><body>
<h2>Admin Portal</h2><p>Use the upload page: <a href="/upload.php">upload.php</a></p>
</body></html>
HTML

# Create simple uploads dir and set ownership
mkdir -p "$ADMIN_ROOT/uploads"
chown -R www-data:www-data "$SITE_ROOT" "$ADMIN_ROOT"
chmod -R 755 "$SITE_ROOT" "$ADMIN_ROOT"

# Create Apache vhost configs
cat > "$APACHE_SITES_DIR/$SITE.conf" <<EOF
<VirtualHost *:80>
    ServerName $SITE
    DocumentRoot $SITE_ROOT
    <Directory $SITE_ROOT>
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/infector_error.log
    CustomLog \${APACHE_LOG_DIR}/infector_access.log combined
</VirtualHost>
EOF

cat > "$APACHE_SITES_DIR/$ADMIN_SITE.conf" <<EOF
<VirtualHost *:80>
    ServerName $ADMIN_SITE
    DocumentRoot $ADMIN_ROOT
    <Directory $ADMIN_ROOT>
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/admin_infector_error.log
    CustomLog \${APACHE_LOG_DIR}/admin_infector_access.log combined
</VirtualHost>
EOF

# Enable sites and reload apache
a2ensite "$SITE.conf" >/dev/null 2>&1 || true
a2ensite "$ADMIN_SITE.conf" >/dev/null 2>&1 || true
a2dissite 000-default.conf >/dev/null 2>&1 || true
systemctl reload apache2

# Secure permissions
chown -R www-data:www-data "$SITE_ROOT" "$ADMIN_ROOT" "$DATA_DIR"
find "$SITE_ROOT" -type d -exec chmod 755 {} \;
find "$SITE_ROOT" -type f -exec chmod 644 {} \;

# Configure UFW (allow only 22 and 80)
if command -v ufw >/dev/null 2>&1; then
  ufw --force reset
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw --force enable
fi

# Final output
echo "================================================================"
echo "Infector web setup complete."
echo ""
echo "Site root: $SITE_ROOT"
echo "Admin root: $ADMIN_ROOT"
echo ""
echo "Admin token (hidden file): $ADMIN_TOKEN_FILE"
echo "Admin token contents:"
cat "$ADMIN_TOKEN_FILE" 2>/dev/null || echo "(token file missing)"
echo ""
echo "Hidden creds (MD5 password) located at: $CREDS_FILE"
echo "Example: /var/www/Infector.htb/public_html/data/creds.json"
echo ""
echo "Visit http://$SITE and http://$ADMIN_SITE on this host (or add VM IP to your attacker's /etc/hosts)."
echo "================================================================"
