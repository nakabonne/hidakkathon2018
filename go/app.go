package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	tagCount map[int]int
)

var (
	db          *sql.DB
	store       *sessions.CookieStore
	redisClient redis.Conn
	loginMu     sync.Mutex
)

type HeaderInfo struct {
	Title   string
	Current string
	Write   bool
}

var headerInfo = HeaderInfo{
	Title:   "Jiriqi:Team",
	Current: "",
	Write:   true,
}

type User struct {
	ID       int
	NickName string
	Email    string
	Passhash string
}

type Article struct {
	ID          int
	AuthorId    int
	Title       string
	Description string
	UpdatedAt   time.Time
	CreatedAt   time.Time
}

type ArticleRelateTags struct {
	ArticleId int
	TagId     int
}

type PopularArticle struct {
	ArticleId int
	IineCnt   int
}

type Iine struct {
	ID        int
	ArticleId int
	UserId    int
	UpdatedAt time.Time
}

type TagName struct {
	ID        int
	Name      string
	CreatedAt time.Time
}

var (
	ErrAuthentication  = errors.New("authentication error")
	ErrContentNotFound = errors.New("content not found")
)

func authenticate(w http.ResponseWriter, r *http.Request, email, passwd string) {
	query := `SELECT u.id AS id, nick_name AS nick_name, u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
WHERE u.email = ? AND u.passhash = SHA2(CONCAT(?, s.salt), 512)`
	row := db.QueryRow(query, email, passwd)
	user := User{}
	err := row.Scan(&user.ID, &user.NickName, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			checkErr(ErrAuthentication)
		}
		checkErr(err)
	}
	session := getSession(r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
	setLogin(user.ID)
}

func getCurrentUser(w http.ResponseWriter, r *http.Request) *User {
	u := context.Get(r, "user")
	if u != nil {
		user := u.(User)
		return &user
	}
	session := getSession(r)
	userID, ok := session.Values["user_id"]
	if !ok || userID == nil {
		return nil
	}
	row := db.QueryRow(`SELECT id, nick_name, email FROM users WHERE id=?`, userID)
	user := User{}
	err := row.Scan(&user.ID, &user.NickName, &user.Email)
	if err == sql.ErrNoRows {
		checkErr(ErrAuthentication)
	}
	checkErr(err)

	context.Set(r, "user", user)
	return &user
}

func getUser(userID int) *User {
	row := db.QueryRow(`SELECT * FROM users WHERE id = ?`, userID)
	user := User{}
	err := row.Scan(&user.ID, &user.NickName, &user.Email, new(string))
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)
	return &user
}

func getIineCount(articleId int) int {
	row := db.QueryRow(`SELECT COUNT(id) as cnt FROM iines WHERE article_id = ?`, articleId)
	cnt := new(int)
	err := row.Scan(cnt)
	checkErr(err)
	return *cnt
}

func getTagCount(tagId int) int {
	if tagCount != nil {
		cnt, _ := tagCount[tagId]
		return cnt
	}
	tagCount = map[int]int{}
	rows, err := db.Query("select tag_id as id, count(*) as cnt from article_relate_tags group by tag_id;")
	checkErr(err)

	defer rows.Close()

	for rows.Next() {
		var id int
		var cnt int
		err := rows.Scan(&id, &cnt)
		checkErr(err)

		tagCount[id] = cnt
	}
	cnt, _ := tagCount[tagId]
	return cnt
}

func getArticle(articleId int) Article {
	row := db.QueryRow(`SELECT * FROM articles WHERE id = ?`, articleId)
	var id, authorId int
	var title, description string
	var createdAt, updatedAt time.Time
	checkErr(row.Scan(&id, &authorId, &title, &description, &updatedAt, &createdAt))

	return Article{id, authorId, title, description, updatedAt, createdAt}
}

func getArticleIineUsers(userId int) []int {
	rows, err := db.Query(`SELECT user_id FROM iines WHERE article_id = ?`, userId)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	var userIds []int
	for rows.Next() {
		var userId int
		checkErr(rows.Scan(&userId))
		userIds = append(userIds, userId)
	}
	rows.Close()
	return userIds
}

func getArticleTagNames(articleId int) []TagName {
	rows, err := db.Query(`SELECT tag_id FROM article_relate_tags WHERE article_id = ? ORDER BY tag_id ASC`, articleId)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	var tagNames []TagName
	for rows.Next() {
		var tagId int
		checkErr(rows.Scan(&tagId))

		row := db.QueryRow(`SELECT tagname FROM tags WHERE id = ?`, tagId)
		tagName := *new(string)
		var createdAt time.Time
		err := row.Scan(&tagName)
		checkErr(err)

		tagNames = append(tagNames, TagName{tagId, tagName, createdAt})
	}
	rows.Close()
	return tagNames
}

func getArticleCount(authorId int) int {
	row := db.QueryRow(`SELECT COUNT(*) as cnt FROM articles WHERE author_id = ?`, authorId)
	var cnt int
	err := row.Scan(&cnt)
	checkErr(err)

	return cnt
}

func deltaTime(updateTime time.Time) string {
	delta := time.Since(updateTime)
	if int(delta.Hours()/(24*30*12)) > 0 {
		return strconv.Itoa(int(delta.Hours()/(24*30*12))) + "年前"
	}
	if int(delta.Hours()/(24*30)) > 0 {
		return strconv.Itoa(int(delta.Hours()/(24*30))) + "ヶ月前"
	}
	if int(delta.Hours()/24) > 0 {
		return strconv.Itoa(int(delta.Hours()/(24))) + "日前"
	}
	if int(delta.Hours()) > 0 {
		return strconv.Itoa(int(delta.Hours())) + "時間前"
	}
	if int(delta.Minutes()) > 0 {
		return strconv.Itoa(int(delta.Minutes())) + "分前"
	}
	return "たったいま"
}

func getPopularArticles() []PopularArticle {
	rows, err := db.Query(`
    SELECT
      article_id,
      count(id) as iineCnt
    FROM
      iines
    GROUP BY
      article_id
    ORDER BY
      iineCnt DESC,
      article_id DESC
    LIMIT 5`)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	popularArticles := make([]PopularArticle, 0, 5)
	for rows.Next() {
		var articleId, iineCount int
		checkErr(rows.Scan(&articleId, &iineCount))

		popularArticles = append(popularArticles, PopularArticle{articleId, iineCount})
	}
	rows.Close()
	return popularArticles
}

func InsArticle(userId int, title string, tags string, articleBody string, tx *sql.Tx) (string, error) {
	query := "INSERT INTO articles ( author_id, title, description, updated_at, created_at ) VALUES ( ?, ?, ?, NOW(), NOW())"
	stmt, err := tx.Prepare(query)
	if err != nil {
		return "", err
	}
	defer stmt.Close()

	result, err := stmt.Exec(userId, title, articleBody)
	if err != nil {
		return "", err
	}
	articleId, err := result.LastInsertId()
	if err != nil {
		return "", err
	}
	if tags != "" {
		tagArray := strings.Split(tags, ",")
		var articleTagIds []int
		for _, tag := range tagArray {
			query = "SELECT id FROM tags WHERE tagname = ?"
			row := db.QueryRow(query, tag)
			var tagId int
			err := row.Scan(&tagId)
			if err != sql.ErrNoRows {
				checkErr(err)

				articleTagIds = append(articleTagIds, tagId)
			} else {
				query = "INSERT INTO tags (tagname) VALUES ( ? )"
				stmt, err = tx.Prepare(query)
				if err != nil {
					return "", err
				}
				result, err := stmt.Exec(tag)
				if err != nil {
					return "", err
				}
				lastArticleTagId, err := result.LastInsertId()
				if err != nil {
					return "", err
				}
				articleTagIds = append(articleTagIds, int(lastArticleTagId))
			}
		}
		for _, articleTagId := range articleTagIds {
			query = "INSERT INTO article_relate_tags (article_id, tag_id) VALUES ( ?, ? )"
			stmt, err = tx.Prepare(query)
			_, err := stmt.Exec(articleId, articleTagId)
			if err != nil {
				return "", err
			}
			_, ok := tagCount[articleTagId]
			if !ok {
				tagCount[articleTagId] = 1
			} else {
				tagCount[articleTagId]++
			}
		}
	}
	return strconv.FormatInt(articleId, 10), nil
}

func UpdArticle(userId int, articleId int, title string, tags string, articleBody string, tx *sql.Tx) error {
	query := "UPDATE articles set title = ? , description = ?, updated_at = NOW() WHERE id = ?"
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(title, articleBody, articleId)
	if err != nil {
		return err
	}
	if tags != "" {
		tagArray := strings.Split(tags, ",")
		var articleTagIds []int
		for _, tag := range tagArray {
			query = "SELECT id FROM tags WHERE tagname = ?"
			row := db.QueryRow(query, tag)
			var tagId int
			err := row.Scan(&tagId)
			if err != sql.ErrNoRows {
				checkErr(err)

				articleTagIds = append(articleTagIds, tagId)
			} else {
				query = "INSERT INTO tags (tagname) VALUES ( ? )"
				stmt, err = tx.Prepare(query)
				if err != nil {
					return err
				}
				result, err := stmt.Exec(tag)
				if err != nil {
					return err
				}
				lastArticleTagId, err := result.LastInsertId()
				if err != nil {
					return err
				}
				articleTagIds = append(articleTagIds, int(lastArticleTagId))
			}
		}
		query := "DELETE FROM article_relate_tags  WHERE article_id = ?"
		stmt, err := tx.Prepare(query)
		_, err = stmt.Exec(articleId)
		if err != nil {
			return err
		}
		for _, articleTagId := range articleTagIds {
			query = "INSERT INTO article_relate_tags (article_id, tag_id) VALUES ( ?, ? )"
			stmt, err = tx.Prepare(query)
			_, err := stmt.Exec(articleId, articleTagId)
			if err != nil {
				return err
			}
			_, ok := tagCount[articleTagId]
			if !ok {
				tagCount[articleTagId] = 1
			} else {
				tagCount[articleTagId]++
			}
		}
	}
	return nil
}

func insAndUpdUserPhoto(userId int, photoPath, photoBinary []byte, tx *sql.Tx) error {
	if photoBinary != nil {
		query := `INSERT INTO
								user_photos
								(
									user_id,
									photo_binary,
									updated_at
								)
							VALUES
								( ?, ?, NOW() )
							ON DUPLICATE KEY
							UPDATE
								photo_binary = ?,
								updated_at = NOW();`
		stmt, err := tx.Prepare(query)
		if err != nil {
			return err
		}
		defer stmt.Close()

		_, err = stmt.Exec(userId, photoBinary, photoBinary)
		if err != nil {
			return err
		}
	} else if photoPath != nil {
		query := `INSERT INTO
              user_photos
              (
                user_id,
                photo_path,
                updated_at
              )
            VALUES
              ( ?, ?, NOW() )
            ON DUPLICATE KEY
            UPDATE
              photo_path = ?,
              updated_at = NOW();`
		stmt, err := tx.Prepare(query)
		if err != nil {
			return err
		}
		defer stmt.Close()

		_, err = stmt.Exec(userId, photoPath, photoPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func updatePassword(userId int, currentPassword string, newPassword string, tx *sql.Tx) string {
	row := db.QueryRow(`SELECT
          COUNT(u.id) AS cnt
        FROM
          users u
        JOIN
          salts s ON u.id = s.user_id
        WHERE
          u.id = ?
        AND
          u.passhash = SHA2(CONCAT(?, s.salt), 512);`, userId, currentPassword)
	var cnt int
	checkErr(row.Scan(&cnt))

	if cnt != 1 {
		return "現在のパスワードが違います"
	}
	salt := randomString(6)
	query := "UPDATE users SET passhash = SHA2(CONCAT(?, ?), 512) WHERE id = ?"
	stmt, _ := tx.Prepare(query)
	defer stmt.Close()

	stmt.Exec(newPassword, salt, userId)
	query = "UPDATE salts SET salt =  ? WHERE user_id = ?"
	stmt, _ = tx.Prepare(query)
	defer stmt.Close()

	stmt.Exec(salt, userId)
	return ""
}

func updateNickName(userId int, nickName string, tx *sql.Tx) {
	query := "UPDATE users SET nick_name = ? WHERE id = ?"
	stmt, _ := tx.Prepare(query)
	defer stmt.Close()

	stmt.Exec(nickName, userId)
}

func updateEmail(userId int, email string, tx *sql.Tx) {
	query := "UPDATE users SET email = ? WHERE id = ?"
	stmt, _ := tx.Prepare(query)
	defer stmt.Close()

	stmt.Exec(email, userId)
}

func recoverMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rcv := recover()
			if rcv != nil {
				switch {
				case rcv == ErrAuthentication:
					session := getSession(r)
					delete(session.Values, "user_id")
					session.Save(r, w)
					render(w, r, http.StatusUnauthorized, "login.html", struct{ Message string }{"ログインに失敗しました"})
					return
				default:
					var msg string
					if e, ok := rcv.(runtime.Error); ok {
						msg = e.Error()
					}
					if s, ok := rcv.(string); ok {
						msg = s
					}
					msg = rcv.(error).Error()
					http.Error(w, msg, http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		user := getCurrentUser(w, r)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		setLogin(user.ID)
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "hidakkathon-go.session")
	return session
}

func setLogin(userId int) {
	loginMu.Lock()
	defer loginMu.Unlock()

	redisClient.Do("SET", "login_"+strconv.Itoa(userId), time.Now().UnixNano()/int64(time.Millisecond))
}

func getLoginUsers() []int {
	var onLineUsers []int
	loginMu.Lock()
	defer loginMu.Unlock()

	keys, _ := redis.Strings(redisClient.Do("KEYS", "login_*"))
	for _, key := range keys {
		loginTime, _ := redis.Int(redisClient.Do("GET", key))
		if time.Now().UnixNano()/int64(time.Millisecond)-int64(loginTime) < 60*60*1000 {
			userId, _ := strconv.Atoi(key[6:])
			onLineUsers = append(onLineUsers, userId)
		}
	}
	sort.Ints(onLineUsers)
	return onLineUsers
}

func randomString(length int) string {
	var rs1Letters = []rune("1234567890abcdef")
	b := make([]rune, length)
	for i := range b {
		b[i] = rs1Letters[rand.Intn(len(rs1Letters))]
	}
	return string(b)
}

func register(name string, email string, password string, tx *sql.Tx) (int, error) {
	salt := randomString(6)
	query := "INSERT INTO users (nick_name, email, passhash) VALUES (?, ?, SHA2(CONCAT(?, ?), 512))"
	stmt, err := tx.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	result, err := stmt.Exec(name, email, password, salt)
	if err != nil {
		return 0, err
	}
	userId, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	query = "INSERT INTO salts (user_id, salt) VALUES ( ?, ? )"
	stmt, err = tx.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	_, err = stmt.Exec(userId, salt)
	return int(userId), err
}

func getTemplatePath(file string) string {
	return path.Join("templates", file)
}

func render(w http.ResponseWriter, r *http.Request, status int, file string, data interface{}) {
	fmap := template.FuncMap{
		"getUser": func(id int) *User {
			return getUser(id)
		},
		"getIineCount": func(id int) int {
			return getIineCount(id)
		},
		"getTagCount": func(id int) int {
			return getTagCount(id)
		},
		"getArticle": func(id int) Article {
			return getArticle(id)
		},
		"getArticleIineUsers": func(id int) []int {
			return getArticleIineUsers(id)
		},
		"getArticleTagNames": func(id int) []TagName {
			return getArticleTagNames(id)
		},
		"getArticleCount": func(id int) int {
			return getArticleCount(id)
		},
		"deltaTime": func(updateTime time.Time) string {
			return deltaTime(updateTime)
		},
		"add": func(a int, b int) int {
			return a + b
		},
		"for": func(n int) []int {
			return make([]int, n)
		},
	}
	tpl := template.Must(template.New(file).Funcs(fmap).ParseFiles(getTemplatePath(file), getTemplatePath("header.html")))
	w.WriteHeader(status)
	checkErr(tpl.Execute(w, data))
}

func GetLogin(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusOK, "login.html", struct{ Message string }{"SGE内で培われた技術や知見を横軸全体で共有するサービス"})
}

func PostLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	passwd := r.FormValue("password")
	authenticate(w, r, email, passwd)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetRegist(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusOK, "regist.html", struct{ Message string }{"新規登録して利用を開始しましょう。"})
}

func PostRegist(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	if name == "" || email == "" || password == "" {
		render(w, r, http.StatusOK, "regist.html", struct{ Message string }{"すべて必須入力です"})
		return
	}
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer func() {
		tx.Rollback()
	}()

	userId, err := register(name, email, password, tx)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			if mysqlErr.Number == 1062 {
				render(w, r, http.StatusOK, "regist.html", struct{ Message string }{"すでに登録済みです"})
				return
			}
			render(w, r, http.StatusOK, "regist.html", struct{ Message string }{mysqlErr.Message})
		}
	}
	session := getSession(r)
	session.Values["user_id"] = userId
	session.Save(r, w)
	tx.Commit()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func GetPhoto(w http.ResponseWriter, r *http.Request) {
	memberID, _ := mux.Vars(r)["member_id"]
	row := db.QueryRow("SELECT * FROM user_photos WHERE user_id = ?", memberID)
	var userId int
	var photoPath string
	var photoPathBytes, photoBinary []byte
	var updatedAt time.Time
	err := row.Scan(&userId, &photoPathBytes, &photoBinary, &updatedAt)
	var body []byte
	if err == sql.ErrNoRows {
		body, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAA3klEQVR42u3SAQ0AAAgDIN8/9K3hJmQgnXZ4KwIIIIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACCCAAAIIIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAA3LNkJfxBbCdD2AAAAAElFTkSuQmCC")
	} else if photoBinary != nil {
		body = photoBinary
	} else {
		photoPath = string(photoPathBytes)
		data, err := ioutil.ReadFile("../static/photo/" + photoPath)
		if err == nil {
			body = data
		}
	}
	w.Header().Set("Content-type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}

func GetIndex(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	page, _ := strconv.Atoi(r.FormValue("page"))
	pageSize := 20
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	row := db.QueryRow("SELECT COUNT(*) as cnt FROM articles")
	var cnt int
	checkErr(row.Scan(&cnt))

	maxPage := int(math.Ceil(float64(cnt) / float64(pageSize)))
	rows, err := db.Query(`SELECT * FROM articles ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	articles := make([]Article, 0, pageSize)
	for rows.Next() {
		var id, authorId int
		var title, description string
		var createdAt, updatedAt time.Time
		checkErr(rows.Scan(&id, &authorId, &title, &description, &updatedAt, &createdAt))

		articles = append(articles, Article{id, authorId, title, description, updatedAt, createdAt})
	}
	rows.Close()

	headerInfo.Current = "new"
	headerInfo.Write = true
	render(w, r, http.StatusOK, "index.html", struct {
		User            User
		Articles        []Article
		PopularArticles []PopularArticle
		OnlineUsers     []int
		Page            int
		MaxPage         int
		HeaderInfo      HeaderInfo
	}{
		*user,
		articles,
		getPopularArticles(),
		getLoginUsers(),
		page,
		maxPage,
		headerInfo,
	})
}

func GetTags(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	row := db.QueryRow("SELECT COUNT(*) as cnt FROM tags")
	var cnt int
	checkErr(row.Scan(&cnt))

	page, _ := strconv.Atoi(r.FormValue("page"))
	pageSize := 20
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	maxPage := int(math.Ceil(float64(cnt) / float64(pageSize)))
	rows, err := db.Query(`
			SELECT
				*
			FROM
				tags
			ORDER BY
				tagname
			LIMIT ? OFFSET ?
		`, pageSize, offset)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	tagNames := make([]TagName, 0, pageSize)
	for rows.Next() {
		var tagId int
		var name string
		var createdAt time.Time
		checkErr(rows.Scan(&tagId, &name, &createdAt))

		tagNames = append(tagNames, TagName{tagId, name, createdAt})
	}
	rows.Close()

	headerInfo.Current = "tags"
	headerInfo.Write = true
	render(w, r, http.StatusOK, "tags.html", struct {
		User       User
		TagNames   []TagName
		Page       int
		MaxPage    int
		MaxCount   int
		HeaderInfo HeaderInfo
	}{
		*user,
		tagNames,
		page,
		maxPage,
		cnt,
		headerInfo,
	})
}

func GetTag(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	tagId := mux.Vars(r)["tag_id"]

	var cnt int
	if tagCount != nil {
		c, err := strconv.Atoi(tagId)
		checkErr(err)
		cnt, _ = tagCount[c]
	} else {
		row := db.QueryRow("SELECT COUNT(*) as cnt FROM article_relate_tags WHERE tag_id = ?", tagId)
		checkErr(row.Scan(&cnt))
	}

	page, _ := strconv.Atoi(r.FormValue("page"))
	pageSize := 20
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	maxPage := int(math.Ceil(float64(cnt) / float64(pageSize)))
	query := `SELECT
				*
			FROM
				article_relate_tags
			WHERE
				tag_id = ?
			ORDER BY
				article_id DESC
			LIMIT ? OFFSET ?`
	rows, err := db.Query(query, tagId, pageSize, offset)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	articleRelateTags := make([]ArticleRelateTags, 0, pageSize)
	for rows.Next() {
		var articleId, tagId int
		checkErr(rows.Scan(&articleId, &tagId))

		articleRelateTags = append(articleRelateTags, ArticleRelateTags{articleId, tagId})
	}
	rows.Close()

	headerInfo.Current = ""
	headerInfo.Write = true
	render(w, r, http.StatusOK, "tag.html", struct {
		User              User
		ArticleRelateTags []ArticleRelateTags
		TagId             string
		Page              int
		MaxPage           int
		MaxCount          int
		HeaderInfo        HeaderInfo
	}{
		*user,
		articleRelateTags,
		tagId,
		page,
		maxPage,
		cnt,
		headerInfo,
	})
}

func GetMembers(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	row := db.QueryRow("SELECT COUNT(*) as cnt FROM users")
	var cnt int
	checkErr(row.Scan(&cnt))
	page, _ := strconv.Atoi(r.FormValue("page"))
	pageSize := 20
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	maxPage := int(math.Ceil(float64(cnt) / float64(pageSize)))
	rows, err := db.Query(`
			SELECT
				*
			FROM
				users
			ORDER BY
				id
			LIMIT ? OFFSET ?
		`, pageSize, offset)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	members := make([]User, 0, pageSize)
	for rows.Next() {
		var id int
		var nickName, email, passhash string
		checkErr(rows.Scan(&id, &nickName, &email, &passhash))

		members = append(members, User{id, nickName, email, passhash})
	}
	rows.Close()

	headerInfo.Current = "members"
	headerInfo.Write = true
	render(w, r, http.StatusOK, "members.html", struct {
		User       User
		Members    []User
		Page       int
		MaxPage    int
		MaxCount   int
		HeaderInfo HeaderInfo
	}{
		*user,
		members,
		page,
		maxPage,
		cnt,
		headerInfo,
	})
}

func GetMember(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	memberId, _ := strconv.Atoi(mux.Vars(r)["member_id"])
	row := db.QueryRow("SELECT COUNT(*) as cnt FROM articles WHERE author_id = ?", memberId)
	var cnt int
	checkErr(row.Scan(&cnt))

	page, _ := strconv.Atoi(r.FormValue("page"))
	pageSize := 20
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	maxPage := int(math.Ceil(float64(cnt) / float64(pageSize)))
	rows, err := db.Query(`
			SELECT
				*
			FROM
				articles
			WHERE
				author_id = ?
			ORDER BY
				updated_at DESC,
				id DESC
			LIMIT ? OFFSET ?
		`, memberId, pageSize, offset)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	articles := make([]Article, 0, pageSize)
	for rows.Next() {
		var id, authorId int
		var title, description string
		var updatedAt, createdAt time.Time
		checkErr(rows.Scan(&id, &authorId, &title, &description, &updatedAt, &createdAt))

		articles = append(articles, Article{id, authorId, title, description, updatedAt, createdAt})
	}
	rows.Close()

	author := getUser(memberId)
	headerInfo.Current = "members"
	headerInfo.Write = true
	render(w, r, http.StatusOK, "member.html", struct {
		User       User
		Author     User
		Articles   []Article
		Page       int
		MaxPage    int
		MaxCount   int
		HeaderInfo HeaderInfo
	}{
		*user,
		*author,
		articles,
		page,
		maxPage,
		cnt,
		headerInfo,
	})
}

func GetArticle(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	articleId, _ := strconv.Atoi(mux.Vars(r)["article_id"])
	row := db.QueryRow("SELECT COUNT(id) as cnt FROM iines WHERE article_id =? AND user_id = ?", articleId, user.ID)
	var cnt int
	checkErr(row.Scan(&cnt))

	headerInfo.Current = ""
	headerInfo.Write = true
	render(w, r, http.StatusOK, "article.html", struct {
		User       User
		ArticleId  int
		Article    Article
		DoneIine   int
		HeaderInfo HeaderInfo
	}{
		*user,
		articleId,
		getArticle(articleId),
		cnt,
		headerInfo,
	})
}

func PostIine(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	articleId, _ := strconv.Atoi(mux.Vars(r)["article_id"])
	sign := r.FormValue("name")
	var query string
	if sign == "plus" {
		query = "INSERT INTO iines (article_id, user_id) VALUES( ?, ? )"
	} else {
		query = "DELETE FROM iines WHERE article_id = ? AND user_id = ?"
	}
	_, err := db.Exec(query, articleId, user.ID)
	checkErr(err)

	var cnt int
	row := db.QueryRow("SELECT COUNT(id) as cnt FROM iines WHERE article_id = ?", articleId)
	checkErr(row.Scan(&cnt))

	w.Write([]byte(strconv.Itoa(cnt)))
}

func GetWrite(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	headerInfo.Current = ""
	headerInfo.Write = false
	render(w, r, http.StatusOK, "write.html", struct {
		User        User
		Message     string
		Title       string
		Tags        string
		ArticleBody string
		HeaderInfo  HeaderInfo
	}{
		*user,
		"Jiriqiのあがる記事を書こう！",
		"",
		"",
		"",
		headerInfo,
	})
}

func PostWrite(w http.ResponseWriter, r *http.Request) {
	title := r.FormValue("title")
	tags := r.FormValue("tags")
	articleBody := r.FormValue("articleBody")
	user := getCurrentUser(w, r)
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer func() {
		tx.Rollback()
	}()

	articleId, err := InsArticle(user.ID, title, tags, articleBody, tx)
	if err != nil {
		headerInfo.Current = ""
		headerInfo.Write = false
		render(w, r, http.StatusOK, "write.html", struct {
			User        User
			Message     string
			Title       string
			Tags        string
			ArticleBody string
			HeaderInfo  HeaderInfo
		}{
			*user,
			"タイトルが重複しています",
			title,
			tags,
			articleBody,
			headerInfo,
		})
		return
	}
	tx.Commit()
	http.Redirect(w, r, "/article/"+articleId, http.StatusFound)
}

func GetUpdate(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	articleId, _ := strconv.Atoi(mux.Vars(r)["article_id"])
	article := getArticle(articleId)
	tagsArray := getArticleTagNames(articleId)
	tags := ""
	for _, tagName := range tagsArray {
		if tags == "" {
			tags = tagName.Name
		} else {
			tags = tags + "," + tagName.Name
		}
	}
	render(w, r, http.StatusOK, "update.html", struct {
		User       User
		Message    string
		ArticleId  int
		Article    Article
		Tags       string
		HeaderInfo HeaderInfo
	}{
		*user,
		"Jiriqiのあがる記事の更新",
		articleId,
		article,
		tags,
		headerInfo,
	})
}

func PostUpdate(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	title := r.FormValue("title")
	tags := r.FormValue("tags")
	articleId, _ := strconv.Atoi(r.FormValue("article_id"))
	articleBody := r.FormValue("articleBody")
	article := getArticle(articleId)
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer func() {
		tx.Rollback()
	}()

	if user.ID != article.AuthorId {
		return
	}
	err = UpdArticle(user.ID, articleId, title, tags, articleBody, tx)
	if err != nil {
		render(w, r, http.StatusOK, "update.html", struct {
			User       User
			Message    string
			ArticleId  int
			Article    Article
			Tags       string
			HeaderInfo HeaderInfo
		}{
			*user,
			"タイトルが重複しています",
			articleId,
			Article{articleId, article.AuthorId, title, articleBody, article.UpdatedAt, article.CreatedAt},
			tags,
			headerInfo,
		})
		return
	}
	tx.Commit()
	http.Redirect(w, r, "/article/"+strconv.Itoa(articleId), http.StatusFound)
}

func GetProfileUpdate(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	userIdByGet, _ := strconv.Atoi(mux.Vars(r)["user_id"])
	if user.ID != userIdByGet {
		return
	}
	render(w, r, http.StatusOK, "profileupdate.html", struct {
		User       User
		Message    string
		HeaderInfo HeaderInfo
	}{
		*user,
		"プロフィールを変更します",
		headerInfo,
	})
}

func PostProfileUpdate(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	nickName := r.FormValue("nick_name")
	email := r.FormValue("email")
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	iconFile, _, err := r.FormFile("icon_file")
	if err != nil {
		return
	}
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer func() {
		tx.Rollback()
	}()

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(iconFile)
	if len(buffer.Bytes()) > 0 {
		insAndUpdUserPhoto(user.ID, nil, buffer.Bytes(), tx)
	}
	if newPassword != "" {
		errorMessage := updatePassword(user.ID, currentPassword, newPassword, tx)
		if errorMessage != "" {
			render(w, r, http.StatusOK, "profileupdate.html", struct {
				User       User
				Message    string
				HeaderInfo HeaderInfo
			}{
				*user,
				errorMessage,
				headerInfo,
			})
		}
	}
	if nickName != "" {
		updateNickName(user.ID, nickName, tx)
	}
	if email != "" {
		updateEmail(user.ID, email, tx)
	}
	tx.Commit()
	http.Redirect(w, r, "/member/"+strconv.Itoa(user.ID), http.StatusFound)
}

func GetInitialize(w http.ResponseWriter, r *http.Request) {
	db.Exec("DELETE FROM users WHERE id > 5000")
	db.Exec("DELETE FROM user_photos WHERE user_id > 5000")
	db.Exec("DELETE FROM tags WHERE id > 999")
	db.Exec("DELETE FROM iines WHERE id > 50000")
	db.Exec("DELETE FROM articles WHERE id > 7101")
	db.Exec("DELETE FROM salts WHERE user_id > 5000")
	db.Exec("DELETE FROM article_relate_tags WHERE article_id > 7101")
	redisClient.Do("FLUSHALL")
	for i := 1; i < 500; i++ {
		setLogin(i)
	}
}

func main() {
	host := os.Getenv("HIDAKKATHON_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("HIDAKKATHON_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable HIDAKKATHON_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("HIDAKKATHON_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("HIDAKKATHON_DB_PASSWORD")
	dbname := os.Getenv("HIDAKKATHON_DB_NAME")
	if dbname == "" {
		dbname = "hidakkathon"
	}
	ssecret := os.Getenv("HIDAKKATHON_SESSION_SECRET")
	if ssecret == "" {
		ssecret = "hidakkathon"
	}
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true", user, password, host, port, dbname))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	store = sessions.NewCookieStore([]byte(ssecret))
	rhost := os.Getenv("HIDAKKATHON_CACHE_HOST")
	if rhost == "" {
		rhost = "localhost"
	}
	rport := os.Getenv("HIDAKKATHON_CACHE_port")
	if rport == "" {
		rport = "6379"
	}
	redisClient, err = redis.Dial("tcp", rhost+":"+rport)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %s.", err.Error())
	}
	r := mux.NewRouter()
	r.Use(recoverMiddleware)
	l := r.Path("/login").Subrouter()
	l.Methods("GET").HandlerFunc(GetLogin)
	l.Methods("POST").HandlerFunc(PostLogin)
	r.Path("/regist").Methods("GET").HandlerFunc(GetRegist)
	r.Path("/regist").Methods("POST").HandlerFunc(PostRegist)
	r.Path("/logout").Methods("GET").HandlerFunc(GetLogout)
	r.Path("/photo/{member_id}").Methods("GET").HandlerFunc(GetPhoto)
	r.Handle("/", authMiddleware(http.HandlerFunc(GetIndex)))
	r.Path("/tags").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetTags)))
	r.Path("/tag/{tag_id}").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetTag)))
	r.Path("/members").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetMembers)))
	r.Path("/member/{member_id}").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetMember)))
	r.Path("/article/{article_id}").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetArticle)))
	r.Path("/iine/{article_id}").Methods("POST").Handler(authMiddleware(http.HandlerFunc(PostIine)))
	r.Path("/write").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetWrite)))
	r.Path("/write").Methods("POST").Handler(authMiddleware(http.HandlerFunc(PostWrite)))
	r.Path("/update/{article_id}").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetUpdate)))
	r.Path("/update/{article_id}").Methods("POST").Handler(authMiddleware(http.HandlerFunc(PostUpdate)))
	r.Path("/profileupdate/{user_id}").Methods("GET").Handler(authMiddleware(http.HandlerFunc(GetProfileUpdate)))
	r.Path("/profileupdate/{user_id}").Methods("POST").Handler(authMiddleware(http.HandlerFunc(PostProfileUpdate)))
	r.HandleFunc("/initialize", GetInitialize)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("../static")))
	log.Fatal(http.ListenAndServe(":8080", r))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
