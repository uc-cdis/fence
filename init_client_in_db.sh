#/bin/bash

# MEANT FOR LOCAL DEV ONLY

# Run this script to setup a new test database on an already running
# postgres container (set DB_CONTAINER_NAME below)

#### Setting up a database for local development

DB_CONTAINER_NAME="fence_db"
FENCE_CONTAINER_NAME="fence"



# Create DB, add test user:
docker exec -i \
$DB_CONTAINER_NAME \
psql -U postgres -d postgres -c 'create database fence_test'

docker exec -i \
$DB_CONTAINER_NAME \
psql -U postgres -d postgres -c "create user test with password 'test' superuser"


sleep 6

# init DB:
# docker exec -i \
# $FENCE_CONTAINER_NAME \
# userdatamodel-init --host "$DB_CONTAINER_NAME" --db fence_test --username test --password test

docker exec -i  -w /fence/ \
$FENCE_CONTAINER_NAME \
alembic upgrade head


docker exec -i \
$DB_CONTAINER_NAME \
psql -U postgres -d fence_test -c "insert into \"User\" (id, username, email) values (10, 'test', 'test@test.uchicago.edu'); commit;"

sleep 6

# add Atlas as client:  (REMEMBER TO ADJUST URL to match your WEBAPI installation!)
docker exec -i \
$FENCE_CONTAINER_NAME \
fence-create client-create --client ATLAS --urls http://127.0.0.1/WebAPI/user/oauth/callback?client_name=OidcClient --username ATLAS
