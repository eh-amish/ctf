#!/usr/bin/env bash
# Infector.htb auto-provision script
# Run as root on fresh Ubuntu Server 24.04 LTS
# Sets up two vhosts (Infector.htb and admin.Infector.htb), login/register flow,
# role-manipulation token, admin upload -> RCE, writable backup cron, randomized flags,
# and firewall to allow only ports 22 and 80.
set -euo pipefail
IFS=$'\n\t'

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "==> Starting Infector.htb provisioning..."

# Variables
WEB_ROOT="/var/www"
SITE_ROOT="$WEB_ROOT/Infector.htb"
ADMIN_ROOT="$WEB_ROOT/admin.Infector.htb"
DATA_DIR="$SITE_ROOT/data"
ADMIN_UPLOADS="$ADMIN_ROOT/uploads"
HOSTNAME="Infector"
ADMIN_TOKEN_FILE="$DATA_DIR/admin_token.txt"
CREDS_FILE="$DATA_DIR/creds.json"
BACKUP_SCRIPT="/usr/local/bin/backup.sh"
CRON_FILE="/etc/cron.d/infector_backup"
APACHE_SITES="/etc/apache2/sites-available"
SSH_PORT=22

# Ensure hostname
hostnamectl set-hostname "$HOSTNAME"
echo "127.0.0.1 $HOSTNAME.htb $HOSTNAME" >> /etc/hosts

# Update & install required packages
export DEBIAN_FRONTEND=noninteractive
apt update
apt -y upgrade
apt install -y apache2 php php-cli php-mbstring php-xml php-curl unzip wget ufw cron openssh-server

# Create directories
mkdir -p "$SITE_ROOT/public_html"
mkdir -p "$ADMIN_ROOT/public_html"
mkdir -p "$DATA_DIR"
mkdir -p "$ADMIN_UPLOADS"
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

# Create no-history global (redirect interactive shell history)
cat > /etc/profile.d/no_history.sh <<'EOF'
#!/bin/sh
export HISTFILE=/dev/null
EOF
chmod 644 /etc/profile.d/no_history.sh

# Generate admin token (random) and write to file
ADMIN_TOKEN=$(openssl rand -hex 16)
mkdir -p "$DATA_DIR"
echo "$ADMIN_TOKEN" > "$ADMIN_TOKEN_FILE"
chown www-data:www-data "$ADMIN_TOKEN_FILE"
chmod 640 "$ADMIN_TOKEN_FILE"

# Create hidden credentials JSON (MD5 of rockmyworld)
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

# Create nspire user with password rockmyworld (no special forbidden chars)
useradd -m -s /bin/bash nspire || true
echo "nspire:rockmyworld" | chpasswd

# Create the web application files (Infector.htb)
cat > "$SITE_ROOT/public_html/index.php" <<'PHP'
<?php
echo "<h1>Welcome to Infector.htb</h1>";
echo "<p>Register: <a href='/register.php'>/register</a> | Login: <a href='/login.php'>/login</a></p>";
?>
PHP

cat > "$SITE_ROOT/public_html/register.php" <<'PHP'
<?php
// Simple registration: email + password -> saved to data/users.json
$data_file = __DIR__ . '/data/users.json';
if (!file_exists($data_file)) { file_put_contents($data_file, json_encode([])); }
$users = json_decode(file_get_contents($data_file), true);
$msg = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    if ($email && $password) {
        $id = count($users) + 1;
        $users[] = ['id'=> (string)$id, 'username' => explode('@',$email)[0], 'email'=>$email, 'password'=>password_hash($password, PASSWORD_DEFAULT)];
        file_put_contents($data_file, json_encode($users));
        $msg = "Registered successfully. You may login.";
    } else {
        $msg = "Provide email and password.";
    }
}
?>
<h2>Register</h2>
<p style="color:green;"><?=htmlspecialchars($msg)?></p>
<form method="post">
Email: <input name="email"><br>
Password: <input name="password" type="password"><br>
<input type="submit" value="Register">
</form>
PHP

cat > "$SITE_ROOT/public_html/login.php" <<'PHP'
<?php
// login: requires username, password, role
$data_file = __DIR__ . '/data/users.json';
$token_file = __DIR__ . '/data/admin_token.txt';
if (!file_exists($data_file)) { file_put_contents($data_file, json_encode([])); }
$users = json_decode(file_get_contents($data_file), true);
$resp = ['status' => 'failed', 'message' => 'Invalid credentials'];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'user';
    $ok = false;
    foreach ($users as $u) {
        if ($u['username'] === $username && password_verify($password, $u['password'])) {
            $ok = true;
            break;
        }
    }
    if ($role === 'admin') {
        // intentional vulnerability: always return admin token even if login fails
        $token = trim(file_get_contents($token_file));
        $resp['token'] = $token;
        $resp['status'] = 'failed';
        $resp['message'] = 'Invalid credentials';
    } elseif ($ok) {
        // successful login normal user
        $resp['status'] = 'success';
        $resp['message'] = 'Login successful';
        $resp['token'] = bin2hex(random_bytes(12));
    } else {
        $resp['status'] = 'failed';
        $resp['message'] = 'Invalid credentials';
    }
    header('Content-Type: application/json');
    echo json_encode($resp);
    exit;
}
?>
<h2>Login</h2>
<form method="post">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
Role: <input name="role" value="user"><br>
<input type="submit" value="Login">
</form>
PHP

# Create data/users.json with a sample user 'alex' (optional)
cat > "$SITE_ROOT/public_html/data/users.json" <<'JSON'
[
  {"id":"1","username":"alex","email":"alex@Infector.htb","password":"$2y$10$kL6KOvQWBq5mMpjI9gHn..s4wnstZrPTcmmH1fukVtqG6R6U1T.ZG"},
  {"id":"2","username":"admin","email":"admin@Infector.htb","password":"$2y$10$vSd5PUe8vF5.q/x5rhT3BO0EcdOPGZClEv9gOdLgF6q2x/Nk7JHL2"}
]
JSON

# Put the admin token file in site data (so login.php can read it if needed)
echo "$ADMIN_TOKEN" > "$SITE_ROOT/public_html/data/admin_token.txt"
chown -R www-data:www-data "$SITE_ROOT"

# Create admin vhost app (admin.Infector.htb) with upload and token check
cat > "$ADMIN_ROOT/public_html/index.php" <<'PHP'
<?php
echo "<h2>Admin Panel</h2>";
echo "<p>Upload: <a href='upload.php'>Upload</a></p>";
?>
PHP

cat > "$ADMIN_ROOT/public_html/upload.php" <<'PHP'
<?php
// Upload page. Requires admin token via header 'X-Auth-Token' or GET param token
$token_file = '/var/www/Infector.htb/public_html/data/admin_token.txt';
$expected = trim(@file_get_contents($token_file));
$provided = '';
// Accept token in header or GET/POST for convenience
if (!empty($_SERVER['HTTP_X_AUTH_TOKEN'])) { $provided = $_SERVER['HTTP_X_AUTH_TOKEN']; }
if (!$provided && isset($_GET['token'])) { $provided = $_GET['token']; }
if (!$provided && isset($_POST['token'])) { $provided = $_POST['token']; }

if ($provided !== $expected) {
    http_response_code(403);
    echo "Forbidden: valid admin token required.";
    exit;
}

$upload_dir = __DIR__ . '/uploads';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $basename = basename($_FILES['file']['name']);
    $dest = $upload_dir . '/' . $basename;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo "Uploaded to /uploads/{$basename}";
    } else {
        echo "Upload failed";
    }
    exit;
}
?>
<h3>Admin Upload</h3>
<form method="post" enctype="multipart/form-data">
<input type="file" name="file"><br>
<input type="submit" value="Upload">
</form>
<p>Note: uploaded files are placed in /uploads/ and are publicly accessible.</p>
PHP

# Create uploads dir and set permissions
mkdir -p "$ADMIN_ROOT/public_html/uploads"
chown -R www-data:www-data "$ADMIN_ROOT/public_html/uploads"
chmod 755 "$ADMIN_ROOT/public_html/uploads"
chown -R www-data:www-data "$ADMIN_ROOT"
chmod -R 755 "$ADMIN_ROOT"

# Create admin token file also accessible at expected location (if not present)
if [ ! -f "$SITE_ROOT/public_html/data/admin_token.txt" ]; then
  echo "$ADMIN_TOKEN" > "$SITE_ROOT/public_html/data/admin_token.txt"
  chown www-data:www-data "$SITE_ROOT/public_html/data/admin_token.txt"
  chmod 640 "$SITE_ROOT/public_html/data/admin_token.txt"
fi

# Create Apache vhost configs
cat > "$APACHE_SITES/Infector.htb.conf" <<EOF
<VirtualHost *:80>
    ServerName Infector.htb
    DocumentRoot $SITE_ROOT/public_html
    <Directory $SITE_ROOT/public_html>
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/infector_error.log
    CustomLog \${APACHE_LOG_DIR}/infector_access.log combined
</VirtualHost>
EOF

cat > "$APACHE_SITES/admin.Infector.htb.conf" <<EOF
<VirtualHost *:80>
    ServerName admin.Infector.htb
    DocumentRoot $ADMIN_ROOT/public_html
    <Directory $ADMIN_ROOT/public_html>
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/admin_infector_error.log
    CustomLog \${APACHE_LOG_DIR}/admin_infector_access.log combined
</VirtualHost>
EOF

a2ensite Infector.htb.conf || true
a2ensite admin.Infector.htb.conf || true
a2dissite 000-default.conf || true
systemctl reload apache2

# Write the hidden creds.json into the site data directory (for discovery)
cp "$CREDS_FILE" "$SITE_ROOT/public_html/data/creds.json"
chown www-data:www-data "$SITE_ROOT/public_html/data/creds.json"
chmod 640 "$SITE_ROOT/public_html/data/creds.json"

# Create backup script and cron (writable by group nspire)
cat > "$BACKUP_SCRIPT" <<'BASH'
#!/bin/bash
tar czf /var/backups/web-$(date +%s).tar.gz /var/www/Infector.htb 2>/dev/null
BASH
chmod 775 "$BACKUP_SCRIPT"
chown root:nspire "$BACKUP_SCRIPT"

# Create cron file: run every minute as root
cat > "$CRON_FILE" <<EOF
* * * * * root $BACKUP_SCRIPT
EOF
chmod 644 "$CRON_FILE"

# Make sure cron is running and reload
systemctl enable cron
systemctl restart cron

# Give sudo permission so that 'sudo -l' for nspire shows the intended permission.
# The description says only sudo permissions are available -> show backup script
echo "nspire ALL=(ALL) NOPASSWD: $BACKUP_SCRIPT" > /etc/sudoers.d/infector_nspire
chmod 440 /etc/sudoers.d/infector_nspire

# Create randomized MD5-format flags
USER_FLAG=$(echo -n "$(openssl rand -hex 16)" | md5sum | awk '{print $1}')
ROOT_FLAG=$(echo -n "$(openssl rand -hex 24)" | md5sum | awk '{print $1}')

# Place user flag in /home/nspire/user.txt
echo -n "$USER_FLAG" > /home/nspire/user.txt
chown root:nspire /home/nspire/user.txt
chmod 644 /home/nspire/user.txt

# Place root flag in /root/root.txt
echo -n "$ROOT_FLAG" > /root/root.txt
chown root:root /root/root.txt
chmod 640 /root/root.txt

# Setup firewall: only allow 22 and 80
ufw --force reset
ufw allow 22/tcp
ufw allow 80/tcp
ufw --force enable

# Ensure SSH server enabled
systemctl enable ssh
systemctl restart ssh

# Final ownership/permissions hygiene
chown -R www-data:www-data "$SITE_ROOT"
chown -R www-data:www-data "$ADMIN_ROOT"

# Output summary and next steps
cat <<SUMMARY

Provisioning complete!

== Access info ==
- Web (HTTP): http://Infector.htb  (on server IP)
- Admin panel (requires admin token): http://admin.Infector.htb
  - Admin token (hidden file): $SITE_ROOT/public_html/data/admin_token.txt
  - Note: login endpoint will return this token if POSTed with 'role=admin' even if login fails.

- SSH user: nspire
  - Password: rockmyworld
  - You can ssh: ssh nspire@Infector.htb  (replace host with VM IP or add host entry)

== Flags ==
- /home/nspire/user.txt  (owner root:nspire, perms 644)
- /root/root.txt        (owner root:root, perms 640)
- Flags are random (MD5 format)

== Important files ==
- Site files: $SITE_ROOT/public_html
- Admin files: $ADMIN_ROOT/public_html
- Hidden creds: $SITE_ROOT/public_html/data/creds.json
- Admin token: $SITE_ROOT/public_html/data/admin_token.txt
- Backup script: $BACKUP_SCRIPT (owner root:nspire, perms 775)
- Cron file: $CRON_FILE (runs every minute)

== Notes for test/import ==
1. On your attacker machine, add the VM IP to /etc/hosts:
   <VM-IP>  Infector.htb admin.Infector.htb

2. To simulate the intended exploit flow:
   - POST to /login with role=admin to get token (even though login fails).
   - Use returned token to access admin.Infector.htb/upload (pass as header X-Auth-Token or token GET param).
   - Upload PHP webshell (e.g., <?php system($_GET['cmd']); ?>) and access it to run commands as www-data.
   - Locate /var/www/Infector.htb/public_html/data/creds.json to find nspire creds (password stored as MD5).
   - SSH as nspire using password 'rockmyworld'.
   - Inspect sudo -l (should show permission for $BACKUP_SCRIPT). Edit $BACKUP_SCRIPT (group nspire writable) to inject reverse shell payload.
   - Wait up to 1 minute for cron to run -> root shell.
   - Capture /root/root.txt

SUMMARY

echo
echo "== Admin token (for quick reference) =="
cat "$ADMIN_TOKEN_FILE"
echo
echo "== creds.json (hidden credentials) =="
cat "$SITE_ROOT/public_html/data/creds.json"
echo
echo "INFECTOR HTB PROVISIONING DONE."

# End of script
