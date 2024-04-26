COCKROACHDB_URL=cockroachdb://cockroach:@localhost:26257/userstore?sslmode=disable
migrate-up:
	migrate -database ${COCKROACHDB_URL} -path db/migration up
migrate-down:
	migrate -database ${COCKROACHDB_URL} -path db/migration down
sqlc:
	sqlc generate

.PHONY: migrate-up migrate-down
