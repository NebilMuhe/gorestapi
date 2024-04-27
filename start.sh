set -e

# echo "run db migration"
# migrate -path /app/migration -database "$COCKROACHDB_URL" -verbose up

echo "start the app"
exec "$@"