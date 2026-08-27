.PHONY: up down ps seed-secrets seed-db

up:
	docker compose up -d --build

down:
	docker compose down -v

ps:
	docker compose ps

seed-secrets:
	# Create an example secret in localstack (AWS SM)

	awslocal secretsmanager create-secret --name gen3/fence/minio/example \
		--secret-string '{"access_key_id":"EXAMPLEACCESS","secret_access_key":"EXAMPLESECRET"}' || true

seed-db:
	# Apply minimal schema
	docker compose exec -T db bash -lc "psql -U fence -d fence <<'SQL'
\i /app/docs/DB_SCHEMA.sql
SQL"
