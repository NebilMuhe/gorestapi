set -e

# echo "run db migration"
# migrate -path /app/migration -database "$COCKROACHDB_URL" -verbose up

echo "start the docker app"
# Wait for CockroachDB to start
# sleep 5

# # Create the database
# cockroach sql --insecure -e 'CREATE DATABASE IF NOT EXISTS userstore;'

exec "$@"