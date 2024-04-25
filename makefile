DB_URL=postgresql://root@localhost:26257/userstore?sslmode=disable
migrate-up:
	migrate -path db/migration -database "${DB_URL}" -verbose up
migrate-down:
	migrate -path db/migration -database "${DB_URL}" -verbose down

.PHONY: migrate-up migrate-down
