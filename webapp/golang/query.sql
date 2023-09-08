-- name: GetPostRecentCommentsAndUser :many
SELECT ranked.id, ranked.post_id, ranked.created_at, ranked.comment, ranked.user_id, CAST(ranking as UNSIGNED ),
    u.account_name, u.authority, u.del_flg
FROM (
         SELECT c.id, c.post_id, c.created_at, c.comment, c.user_id,
                RANK() OVER (PARTITION BY post_id ORDER BY created_at DESC ) AS ranking
         FROM comments as c
         WHERE c.post_id IN (sqlc.slice('post_ids'))
     ) as ranked
         LEFT JOIN users as u ON ranked.user_id = u.id
WHERE ranking <= 3
ORDER BY ranked.post_id, ranking DESC;


-- name: GetUsersPosts :many
SELECT p.id, p.user_id, p.mime, p.body, p.created_at,
       account_name, passhash, authority, del_flg
FROM posts as p
         LEFT JOIN users u force index (users_del_flg_index) on u.id = p.user_id
WHERE u.id =?
ORDER BY p.created_at DESC
LIMIT ?;
