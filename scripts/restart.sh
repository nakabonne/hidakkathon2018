#!/bin/bash
set -e

cd /var/www/html/webapp
git pull

sudo cp etc/nginx.conf /etc/nginx/nginx.conf

cd go
make build

sudo /usr/sbin/nginx -t
sudo service nginx reload

sudo systemctl restart systemd.go.service

echo ""
echo "$(tput setaf 2)Restart Succeeded!!! ✔︎$(tput sgr0)"
