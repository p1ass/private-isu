// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0

package sqlc

import (
	"time"
)

type Comment struct {
	ID        int32
	PostID    int32
	UserID    int32
	Comment   string
	CreatedAt time.Time
}

type Post struct {
	ID        int32
	UserID    int32
	Mime      string
	Imgdata   []byte
	Body      string
	CreatedAt time.Time
}

type User struct {
	ID          int32
	AccountName string
	Passhash    string
	Authority   bool
	DelFlg      bool
	CreatedAt   time.Time
}
