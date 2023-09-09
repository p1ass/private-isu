package main

import (
	"context"
	crand "crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/catatsuy/private-isu/webapp/golang/isucache"
	"github.com/catatsuy/private-isu/webapp/golang/sqlc"
	"github.com/riandyrn/otelchi"
	"github.com/uptrace/opentelemetry-go-extra/otelsql"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	_ "net/http/pprof"
)

var (
	db    *sqlx.DB
	store *sessions.CookieStore
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	store = sessions.NewCookieStore([]byte("afasdfa"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
		"CREATE INDEX users_account_name_del_flg_index on users (account_name, del_flg)",
		"create index posts_user_id_created_at_index on posts (user_id asc, created_at desc)",
		"create index comments_post_id_created_at_index on comments (post_id asc, created_at desc)",
		"create index comments_user_id_created_at_index on comments (user_id asc, created_at desc)",
		"create index users_id_del_flg_index on users (id, del_flg)",
		"create index users_del_flg_index on users (del_flg)",
		"create index posts_created_at_index on posts (created_at desc)",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(ctx context.Context, accountName, password string) *User {
	u := User{}
	err := db.GetContext(ctx, &u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	h := sha512.New()
	io.WriteString(h, src)
	sumout := h.Sum(nil)
	return hex.EncodeToString(sumout)
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.GetContext(r.Context(), &u, "SELECT * FROM `users` WHERE `id` = ? LIMIT 1", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makeRecentPosts(ctx context.Context, results []Post) ([]Post, error) {
	var postIDs []int32
	for _, p := range results {
		postIDs = append(postIDs, int32(p.ID))
	}

	querier := sqlc.New(db)
	commentsAndUser, err := querier.GetPostRecentCommentsAndUser(ctx, postIDs)
	if err != nil {
		return nil, err
	}

	for _, p := range results {
		var comments []Comment
		for _, c := range commentsAndUser {
			if p.ID == int(c.PostID) {
				comments = append(comments, Comment{
					ID:        int(c.ID),
					PostID:    int(c.PostID),
					UserID:    int(c.UserID),
					Comment:   c.Comment,
					CreatedAt: c.CreatedAt,
					User: User{
						ID:          int(c.UserID),
						AccountName: c.AccountName.String,
						Passhash:    "",
						Authority:   boolToInt(c.Authority.Bool),
						DelFlg:      boolToInt(c.DelFlg.Bool),
						CreatedAt:   time.Time{},
					},
				})
			}
		}
		p.Comments = comments

		counts, ok := commentCountByPostID.Value(strconv.Itoa(p.ID))
		if ok {
			p.CommentCount = counts
		} else {
			err := db.GetContext(ctx, &p.CommentCount, "SELECT COUNT(1) AS `count` FROM `comments` WHERE `post_id` = ?", p.ID)
			if err != nil {
				return nil, err
			}
			commentCountByPostID.Set(strconv.Itoa(p.ID), p.CommentCount)
		}

	}

	return results, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

// 全てのユーザーの全ての投稿をcreated at descで取得する allComments:false getIndex
// 指定したユーザー全ての投稿をcreated at descで取得する allComments:false getAccountName
// 指定した日付より古い投稿をcreated at descで取得する allComments:false getPosts
// 指定したPostIDの投稿を1つ取得する allComments:true getPostsID
func makePosts(ctx context.Context, result Post) (Post, error) {

	postComments, err := sqlc.New(db).GetComments(ctx, int32(result.ID))
	if err != nil {
		return Post{}, err
	}

	var comments []Comment
	for _, c := range postComments {
		comments = append(comments, Comment{
			ID:        int(c.ID),
			PostID:    int(c.PostID),
			UserID:    int(c.UserID),
			Comment:   c.Comment,
			CreatedAt: c.CreatedAt,
			User: User{
				ID:          int(c.UserID),
				AccountName: c.AccountName.String,
				Passhash:    "",
				Authority:   boolToInt(c.Authority.Bool),
				DelFlg:      boolToInt(c.DelFlg.Bool),
				CreatedAt:   time.Time{},
			},
		})
	}
	result.Comments = comments

	counts, ok := commentCountByPostID.Value(strconv.Itoa(result.ID))
	if ok {
		result.CommentCount = counts
	} else {
		err := db.GetContext(ctx, &result.CommentCount, "SELECT COUNT(1) AS `count` FROM `comments` WHERE `post_id` = ?", result.ID)
		if err != nil {
			return Post{}, err
		}
		commentCountByPostID.Set(strconv.Itoa(result.ID), result.CommentCount)
	}

	return result, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	bothInit()

	// ディレクトリ内のファイル一覧を取得
	files, err := os.ReadDir("/home/image")
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}

	// 各ファイルを削除
	for _, file := range files {
		filePath := filepath.Join("/home/image", file.Name())
		err := os.Remove(filePath)
		if err != nil {
			fmt.Println("Error deleting file:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.Context(), r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.GetContext(r.Context(), &exists, "SELECT 1 FROM users WHERE `account_name` = ? LIMIT 1", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.ExecContext(r.Context(), query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	usersPosts, err := sqlc.New(db).GetUndeletedUsersPosts(r.Context(), postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}
	csrfToken := getCSRFToken(r)
	for _, p := range usersPosts {
		results = append(results, Post{
			ID:           int(p.ID),
			UserID:       int(p.UserID),
			Imgdata:      nil,
			Body:         p.Body,
			Mime:         p.Mime,
			CreatedAt:    p.CreatedAt,
			CommentCount: 0,   // makeRecentPostで入れる
			Comments:     nil, // makeRecentPostsで入れる
			User: User{
				ID:          int(p.UserID),
				AccountName: p.AccountName,
				Passhash:    p.Passhash, // 不要
				Authority:   boolToInt(p.Authority),
				DelFlg:      boolToInt(p.DelFlg),
				CreatedAt:   time.Time{}, // 不要
			},
			CSRFToken: csrfToken,
		})
	}

	posts, err := makeRecentPosts(r.Context(), results)
	if err != nil {
		log.Print(err)
		return
	}

	tracer := otel.Tracer("getIndex")
	_, span := tracer.Start(r.Context(), "templateExecute")

	getIndexTemplate.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, csrfToken, getFlash(w, r, "notice")})
	span.End()
}

var getIndexTemplate = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("index.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	err := db.GetContext(r.Context(), &user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0 LIMIT 1", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	usersPosts, err := sqlc.New(db).GetUsersPosts(r.Context(), sqlc.GetUsersPostsParams{
		ID:    int32(user.ID),
		Limit: postsPerPage,
	})
	if err != nil {
		log.Print(err)
		return
	}
	csrfToken := getCSRFToken(r)
	for _, p := range usersPosts {
		results = append(results, Post{
			ID:           int(p.ID),
			UserID:       int(p.UserID),
			Imgdata:      nil,
			Body:         p.Body,
			Mime:         p.Mime,
			CreatedAt:    p.CreatedAt,
			CommentCount: 0,   // makeRecentPostで入れる
			Comments:     nil, // makeRecentPostsで入れる
			User: User{
				ID:          int(p.UserID),
				AccountName: p.AccountName,
				Passhash:    p.Passhash, // 不要
				Authority:   boolToInt(p.Authority),
				DelFlg:      boolToInt(p.DelFlg),
				CreatedAt:   time.Time{}, // 不要
			},
			CSRFToken: csrfToken,
		})
	}

	posts, err := makeRecentPosts(r.Context(), results)
	if err != nil {
		log.Print(err)
		return
	}

	commentCount := 0
	err = db.GetContext(r.Context(), &commentCount, "SELECT COUNT(1) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	// TODO: アプリケーションがわ で計算できそう
	postIDs := []int{}
	err = db.SelectContext(r.Context(), &postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		for _, postID := range postIDs {
			v, ok := commentCountByPostID.Value(strconv.Itoa(postID))
			if ok {
				commentedCount += v
			}
		}
	}

	me := getSessionUser(r)

	getAccountNameTmpl.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

var getAccountNameTmpl = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("user.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}

	usersPosts, err := sqlc.New(db).GetUndeletedUsersPostsWithMaxCreatedAt(r.Context(), sqlc.GetUndeletedUsersPostsWithMaxCreatedAtParams{
		CreatedAt: t,
		Limit:     postsPerPage,
	})
	if err != nil {
		log.Print(err)
		return
	}
	csrfToken := getCSRFToken(r)
	for _, p := range usersPosts {
		results = append(results, Post{
			ID:           int(p.ID),
			UserID:       int(p.UserID),
			Imgdata:      nil,
			Body:         p.Body,
			Mime:         p.Mime,
			CreatedAt:    p.CreatedAt,
			CommentCount: 0,   // makeRecentPostで入れる
			Comments:     nil, // makeRecentPostsで入れる
			User: User{
				ID:          int(p.UserID),
				AccountName: p.AccountName,
				Passhash:    p.Passhash, // 不要
				Authority:   boolToInt(p.Authority),
				DelFlg:      boolToInt(p.DelFlg),
				CreatedAt:   time.Time{}, // 不要
			},
			CSRFToken: csrfToken,
		})
	}

	posts, err := makeRecentPosts(r.Context(), results)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	getPostTmpl.Execute(w, posts)
}

var getPostTmpl = template.Must(template.New("posts.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	result, err := sqlc.New(db).GetPost(r.Context(), int32(pid))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.Print(err)
		return
	}

	post := Post{
		ID:           int(result.ID),
		UserID:       int(result.UserID),
		Imgdata:      nil,
		Body:         result.Body,
		Mime:         result.Mime,
		CreatedAt:    time.Time{},
		CommentCount: 0,
		Comments:     nil,
		User: User{
			ID:          int(result.UserID),
			AccountName: result.AccountName,
			Passhash:    result.Passhash,
			Authority:   boolToInt(result.Authority),
			DelFlg:      boolToInt(result.DelFlg),
			CreatedAt:   time.Time{}, // 不要
		},
		CSRFToken: getCSRFToken(r),
	}

	post, err = makePosts(r.Context(), post)
	if err != nil {
		log.Print(err)
		return
	}

	me := getSessionUser(r)

	getPostIDTmpl.Execute(w, struct {
		Post Post
		Me   User
	}{post, me})
}

var getPostIDTmpl = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("post_id.html"),
	getTemplPath("post.html"),
))

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	defer file.Close()

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = ".jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = ".png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = ".gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	if header.Size > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`,`imgdata` , `body`) VALUES (?,?,?, ?)"
	result, err := db.ExecContext(r.Context(),
		query,
		me.ID,
		mime,
		[]byte{},
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	err = os.MkdirAll("/home/image", 0777)
	if err != nil {
		log.Print(err)
		return
	}
	f, err := os.Create(fmt.Sprintf("/home/image/%d%s", pid, ext))
	if err != nil {
		log.Print(err)
		return

	}
	defer f.Close()

	_, err = io.Copy(f, file)
	if err != nil {
		log.Print(err)
		return
	}

	commentCountByPostID.Set(strconv.Itoa(int(pid)), 0)

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.GetContext(r.Context(), &post, "SELECT `mime`, `imgdata` FROM `posts` WHERE `id` = ? LIMIT 1", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := chi.URLParam(r, "ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)
		_, err := w.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return
		}

		go func() {
			f, err := os.Create(fmt.Sprintf("/home/image/%d.%s", pid, ext))
			if err != nil {
				log.Print(err)
				return

			}
			defer f.Close()
			_, err = f.Write(post.Imgdata)
			if err != nil {
				log.Print(err)
				return
			}
		}()
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.ExecContext(r.Context(), query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	commentCountByPostID.Inc(strconv.Itoa(postID))

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.SelectContext(r.Context(), &users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.ExecContext(r.Context(), query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

var commentCountByPostID = &isucache.SafeCounter{
	V:   map[string]int{},
	Mux: sync.Mutex{},
}

// 👹main関数からとpostInitialize両方から呼び出されるところに書かなければならない
func bothInit() {
	commentCountByPostID.Reset()
}

func main() {
	bothInit()
	tp, err := initializeTracerProvider()
	if err != nil {
		log.Fatalf("Failed to initialize tracer provider: %v", err)
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}()

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err = strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	stdDb, err := otelsql.Open("mysql", dsn, otelsql.WithDBName("mysql"))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	stdDb.SetMaxIdleConns(10)
	stdDb.SetMaxOpenConns(10)
	db = sqlx.NewDb(stdDb, "mysql")

	defer db.Close()

	r := chi.NewRouter()
	r.Use(otelchi.Middleware("private-isu", otelchi.WithChiRoutes(r)))

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/debug/pprof/*", http.DefaultServeMux.ServeHTTP)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}

func initializeTracerProvider() (*sdktrace.TracerProvider, error) {
	res, err := resource.New(context.Background(), resource.WithTelemetrySDK())
	if err != nil {
		return nil, fmt.Errorf("faield to create resource: %w", err)
	}

	tracerProviderOptions := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.01))),
		sdktrace.WithResource(res),
	}

	// ローカルでJaegerが動いてる場合はJaegerにつなぐ
	ep, ok := os.LookupEnv("JAEGER_ENDPOINT")
	if ok {
		exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(ep)))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize jager: %w", err)
		}
		tracerProviderOptions = append(tracerProviderOptions, sdktrace.WithBatcher(exporter))
	}

	tp := sdktrace.NewTracerProvider(tracerProviderOptions...)
	otel.SetTracerProvider(tp)

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(propagator)

	return tp, nil
}
