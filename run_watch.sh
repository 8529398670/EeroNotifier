#!/usr/bin/env bash

cd /home/sd/DOCKER_IMAGES/EeroNotifier || exit 1

exec flock -n /tmp/eeronotifier.lock \
	/home/sd/DOCKER_IMAGES/EeroNotifier/venv/bin/python watch.py