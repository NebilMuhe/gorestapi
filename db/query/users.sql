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