#! /usr/bin/env bash
docker-compose up -d
docker-compose run --rm backend sh -c 'python manage.py createapp App -u http://localhost:23801/magic --app-id 123456 -r --api-key testkey'
docker-compose run --rm backend sh -c 'python manage.py createapp App2 -u http://localhost:23801/magic --app-id 2 -r --api-key testkey'
