-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, is_chirpy_red)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2,
    $3
)
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;


-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red
from users
where email = $1;

-- name: UpdateUserInfo :one
UPDATE users
SET email = $1,
    hashed_password = $2,
    updated_at = NOW()
WHERE id = $3
RETURNING id, email, created_at, updated_at;

-- name: UpgradeUserToRed :exec
UPDATE users
SET is_chirpy_red = true
WHERE id = $1;