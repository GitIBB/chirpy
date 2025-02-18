-- name: AddRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, expires_at, created_at, updated_at, revoked_at)
VALUES (
    $1,
    $2,
    $3,
    NOW(),
    NOW(),
    NULL
);

-- name: ValidateRefreshToken :one
SELECT users.id, users.email
FROM refresh_tokens
JOIN users on users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1
AND refresh_tokens.expires_at > NOW()
AND refresh_tokens.revoked_at IS NULL;


-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
    updated_at = NOW()
WHERE token = $1;