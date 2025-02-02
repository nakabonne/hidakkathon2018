#!/bin/bash
set -e

# pull
cd /var/www/html/webapp
git pull
echo "$(tput setaf 2)Pull Succeeded! $(tput sgr0)"
echo ""

# reverse proxy reload
sudo cp etc/nginx.conf /etc/nginx/nginx.conf
sudo /usr/sbin/nginx -t
sudo service nginx reload
echo "$(tput setaf 2)reverse proxy reload Succeeded! $(tput sgr0)"
echo ""

# in-memory cache reload
sudo cp etc/redis.conf /etc/redis/redis.conf
sudo systemctl restart redis-server
echo "$(tput setaf 2)in-memory cache reload Succeeded! $(tput sgr0)"
echo ""

# application reload
sudo cp etc/systemd.go.service /etc/systemd/system/systemd.go.service
sudo systemctl daemon-reload
cd go
make build
sudo systemctl restart systemd.go.service
echo "$(tput setaf 2)application reload Succeeded! $(tput sgr0)"
echo ""

echo "$(tput setaf 2)############################$(tput sgr0)"
echo "$(tput setaf 2)## Restart Succeeded!!! ✔︎ ##$(tput sgr0)"
echo "$(tput setaf 2)############################$(tput sgr0)"
echo ""
