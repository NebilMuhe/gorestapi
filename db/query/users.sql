-- name: RegisterUser :one
INSERT INTO users (
  username,
  email,
  password
) VALUES (
  $1, $2, $3
) RETURNING *;

-- name: FindBYEmail :one
SELECT *
FROM users
WHERE email = $1
LIMIT 1;

-- name: FindBYUsername :one
SELECT *
FROM users
WHERE username = $1
LIMIT 1;

-- name: LoginUser :one
SELECT *
FROM users
WHERE username = $1
LIMIT 1;

-- name: CreateSession :one
INSERT INTO sessions (
  username,
  refresh_token
) VALUES (
  $1, $2
) RETURNING *;

-- name: IsLoggedIn :one
SELECT *
FROM sessions
WHERE username = $1
LIMIT 1;

-- name: UpdateSession :one
UPDATE sessions
SET refresh_token = $1
WHERE username = $2
RETURNING *;

-- name: DeleteTable :many
DELETE FROM users RETURNING *;