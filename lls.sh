#!/usr/bin/env bash
# remove_admin_hint.sh
# Removes the visible "admin hint" from index.html safely

set -e

INDEX="/var/www/Infector.htb/public_html/index.html"
BACKUP="/var/www/Infector.htb/public_html/index.html.bak"

echo "[*] Creating backup..."
sudo cp "$INDEX" "$BACKUP"

echo "[*] Removing admin hint span..."
sudo perl -0777 -pe 's#<span[^>]*class="admin-hint"[^>]*>.*?</span>##is' -i "$INDEX"

echo "[*] Reloading Apache..."
sudo systemctl reload apache2

echo "[+] Admin hint removed successfully!"
echo "[+] Backup saved at: $BACKUP"
