#!/bin/bash
set -e

# pull
cd /var/www/html/webapp
git pull

# reverse proxy reload
sudo cp etc/nginx.conf /etc/nginx/nginx.conf
sudo /usr/sbin/nginx -t
sudo service nginx reload

# application reload
sudo cp etc/systemd.go.service /etc/systemd/system/systemd.go.service
sudo systemctl daemon-reload
cd go
make build
sudo systemctl restart systemd.go.service

echo "$(tput setaf 2)############################$(tput sgr0)"
echo "$(tput setaf 2)## Restart Succeeded!!! ✔︎ ##$(tput sgr0)"
echo "$(tput setaf 2)############################$(tput sgr0)"
