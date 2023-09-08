package sqlc

import (
	"context"
	"time"
)

const getUndeletedUsersPosts = `-- name: GetUndeletedUsersPosts :many
SELECT p.id, p.user_id, p.mime, p.body, p.created_at,
       account_name, passhash, authority, del_flg
FROM posts as p,
     LATERAL ( SELECT account_name, passhash, authority, del_flg
               FROM users as u
               WHERE id = p.user_id
               LIMIT 1 ) AS u
WHERE u.del_flg = 0
ORDER BY p.created_at DESC
LIMIT ?;
`

type GetUndeletedUsersPostsRow struct {
	ID          int32
	UserID      int32
	Mime        string
	Body        string
	CreatedAt   time.Time
	AccountName string
	Passhash    string
	Authority   bool
	DelFlg      bool
}

func (q *Queries) GetUndeletedUsersPosts(ctx context.Context, limit int32) ([]GetUndeletedUsersPostsRow, error) {
	rows, err := q.db.QueryContext(ctx, getUndeletedUsersPosts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetUndeletedUsersPostsRow
	for rows.Next() {
		var i GetUndeletedUsersPostsRow
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.Mime,
			&i.Body,
			&i.CreatedAt,
			&i.AccountName,
			&i.Passhash,
			&i.Authority,
			&i.DelFlg,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUndeletedUsersPostsWithMaxCreatedAt = `-- name: GetUndeletedUsersPostsWithMaxCreatedAt :many
SELECT p.id, p.user_id, p.mime, p.body, p.created_at,
       account_name, passhash, authority, del_flg
FROM posts as p,
     LATERAL ( SELECT account_name, passhash, authority, del_flg
               FROM users as u
               WHERE id = p.user_id
               LIMIT 1 ) AS u
WHERE p.created_at <= ? AND u.del_flg = 0
ORDER BY p.created_at DESC
LIMIT ?;
`

type GetUndeletedUsersPostsWithMaxCreatedAtParams struct {
	CreatedAt time.Time
	Limit     int32
}

type GetUndeletedUsersPostsWithMaxCreatedAtRow struct {
	ID          int32
	UserID      int32
	Mime        string
	Body        string
	CreatedAt   time.Time
	AccountName string
	Passhash    string
	Authority   bool
	DelFlg      bool
}

func (q *Queries) GetUndeletedUsersPostsWithMaxCreatedAt(ctx context.Context, arg GetUndeletedUsersPostsWithMaxCreatedAtParams) ([]GetUndeletedUsersPostsWithMaxCreatedAtRow, error) {
	rows, err := q.db.QueryContext(ctx, getUndeletedUsersPostsWithMaxCreatedAt, arg.CreatedAt, arg.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetUndeletedUsersPostsWithMaxCreatedAtRow
	for rows.Next() {
		var i GetUndeletedUsersPostsWithMaxCreatedAtRow
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.Mime,
			&i.Body,
			&i.CreatedAt,
			&i.AccountName,
			&i.Passhash,
			&i.Authority,
			&i.DelFlg,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
