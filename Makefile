MAKEFLAGS = --no-builtin-rules --no-builtin-variables --always-make
.DEFAULT_GOAL := help

SHELL  = /usr/bin/env bash

alp:
	sudo alp -r --sum -f $(file)

restart:
	sh scripts/restart.sh

rotate:
	sh scripts/rotate_alplog.sh
