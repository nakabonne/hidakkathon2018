package main

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	db    *sql.DB
	store *sessions.CookieStore

	iineCount               map[int]int
	iineCountMu             sync.Mutex
	tagArticleCount         map[int]int
	tagArticleCountMu       sync.Mutex
	cachedPopularArticlesMu sync.Mutex
	cachedPopularArticles   []PopularArticle
	articleCountMu          sync.Mutex
	articleCount            map[int]int
	allArticleCountMu       sync.Mutex
	allArticleCount         int

	photoCache   map[int][]byte
	photoCacheMu sync.Mutex

	inMemoryRedis   map[string]int64
	inMemoryRedisMu sync.Mutex
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
	ID             int
	AuthorId       int
	Title          string
	Description    string
	UpdatedAt      time.Time
	CreatedAt      time.Time
	CachedAuthor   User
	CachedTagNames []TagName
}

type PopularArticle struct {
	ArticleId     int
	IineCnt       int
	CachedIine    []*Iine
	CachedArticle *Article
}

type Iine struct {
	ID        int
	ArticleId int
	UpdatedAt time.Time
	UserId    int
}

type TagName struct {
	ID        int
	Name      string
	CreatedAt time.Time
}

var (
	ErrAuthentication  = errors.New("Authentication error.")
	ErrContentNotFound = errors.New("Content not found.")
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
	session := getSession(w, r)
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
	session := getSession(w, r)
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

func getUser(w http.ResponseWriter, userID int) *User {
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
	iineCountMu.Lock()
	defer iineCountMu.Unlock()
	return iineCount[articleId]
}

func getTagCount(tagId int) int {
	tagArticleCountMu.Lock()
	defer tagArticleCountMu.Unlock()
	cnt, ok := tagArticleCount[tagId]
	if !ok {
		panic(sql.ErrNoRows)
	}
	return cnt
}

func getArticle(w http.ResponseWriter, articleId int) Article {
	row := db.QueryRow(`SELECT * FROM articles WHERE id = ?`, articleId)
	var id, authorId int
	var title, description string
	var createdAt, updatedAt time.Time
	checkErr(row.Scan(&id, &authorId, &title, &description, &updatedAt, &createdAt))
	return Article{ID: id, AuthorId: authorId, Title: title, Description: description, UpdatedAt: updatedAt, CreatedAt: createdAt}
}

func getArticleIineUsers(userId int) []int {
	rows, err := db.Query(`SELECT user_id FROM iines WHERE article_id = ?`, userId)
	defer rows.Close()

	if err != sql.ErrNoRows {
		checkErr(err)
	}
	var userIds []int
	for rows.Next() {
		var userId int
		checkErr(rows.Scan(&userId))
		userIds = append(userIds, userId)
	}

	return userIds
}

func getArticleTagNames(articleId int) []TagName {
	rows, err := db.Query(`SELECT t.id, t.tagname FROM article_relate_tags AS ar LEFT JOIN tags AS t ON ar.tag_id = t.id WHERE article_id = ? ORDER BY tag_id ASC`, articleId)
	defer rows.Close()

	if err != sql.ErrNoRows {
		checkErr(err)
	}
	tagNames := make([]TagName, 0, 50)
	for rows.Next() {
		t := TagName{}
		err := rows.Scan(&t.ID, &t.Name)
		checkErr(err)
		tagNames = append(tagNames, t)
	}
	return tagNames
}

func getArticleCount(authorId int) int {
	articleCountMu.Lock()
	defer articleCountMu.Unlock()
	return articleCount[authorId]
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
	if cachedPopularArticles != nil {
		return cachedPopularArticles[:5]
	}
	rowsA, err := db.Query(`
    SELECT
      article_id,
      count(user_id) as iineCnt
    FROM
      iines
    WHERE
      updated_at >= DATE_ADD(NOW(), INTERVAL -1 MONTH)
    GROUP BY
      article_id
    ORDER BY
      iineCnt DESC,
      article_id DESC
    LIMIT ?`, 300)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	defer rowsA.Close()

	popularArticles := make([]PopularArticle, 0, 5)
	for rowsA.Next() {
		var articleId, iineCount int
		checkErr(rowsA.Scan(&articleId, &iineCount))
		p := PopularArticle{ArticleId: articleId, IineCnt: iineCount}
		p.CachedIine = make([]*Iine, 0, 50)
		popularArticles = append(popularArticles, p)
	}

	l := len(popularArticles)
	if l == 0 {
		return popularArticles
	}

	queryParts := "?"
	args := make([]interface{}, l)
	args[0] = popularArticles[0].ArticleId
	for i := 1; i < l; i++ {
		queryParts += ", ?"
		args[i] = popularArticles[i].ArticleId
	}

	query := fmt.Sprintf(`SELECT a.id, a.author_id, a.title, a.description, a.updated_at, a.created_at, i.id, i.article_id, i.user_id, i.updated_at FROM articles as a LEFT JOIN iines as i ON i.article_id = a.id WHERE a.id IN (%s) `, queryParts)
	rowsB, err := db.Query(query, args...)
	defer rowsB.Close()

	for rowsB.Next() {
		article := new(Article)
		iine := new(Iine)
		err = rowsB.Scan(&article.ID, &article.AuthorId, &article.Title, &article.Description, &article.UpdatedAt, &article.CreatedAt, &iine.ID, &iine.ArticleId, &iine.UserId, &iine.UpdatedAt)
		if err != nil {
			panic(err)
		}

		index := inPopularArticles(popularArticles, article.ID)
		if popularArticles[index].CachedArticle == nil {
			popularArticles[index].CachedArticle = article
		}
		popularArticles[index].CachedIine = append(popularArticles[index].CachedIine, iine)
	}

	cachedPopularArticlesMu.Lock()
	defer cachedPopularArticlesMu.Unlock()

	cachedPopularArticles = popularArticles
	return popularArticles[:5]
}

func inPopularArticles(populars []PopularArticle, articleId int) (index int) {
	for i := range populars {
		if articleId == populars[i].ArticleId {
			return i
		}
	}
	panic("article not found")
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
	tagArticleCountMu.Lock()
	defer tagArticleCountMu.Unlock()

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
			tagArticleCount[articleTagId]++
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
	tagArticleCountMu.Lock()
	defer tagArticleCountMu.Unlock()

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

		tags := getArticleTagNames(articleId)
		for i := range tags {
			tagArticleCount[tags[i].ID]--
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
			tagArticleCount[articleTagId]++
		}
	}
	return nil
}

func insAndUpdUserPhoto(userId int, photoBinary []byte, tx *sql.Tx) error {
	photoCacheMu.Lock()
	defer photoCacheMu.Unlock()
	photoCache[userId] = photoBinary

	query := `INSERT INTO user_photos
		(
			user_id,
			photo_binary,
			updated_at
		)
	VALUES
		( ?, ?, NOW() )
	ON DUPLICATE KEY
	UPDATE
		updated_at = NOW();`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(userId, []byte{})
	if err != nil {
		return err
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
					session := getSession(w, r)
					delete(session.Values, "user_id")
					session.Save(r, w)
					render(w, r, http.StatusUnauthorized, "login.html", struct{ Message string }{"ログインに失敗しました"})
					return
				default:
					var msg string
					if e, ok := rcv.(runtime.Error); ok {
						msg = e.Error()
					}
					stacktrace := ""
					for depth := 0; ; depth++ {
						_, file, line, ok := runtime.Caller(depth)
						if !ok {
							break
						}
						if strings.HasSuffix(file, "app.go") {
							stacktrace += fmt.Sprintf("====> %d: %v:%d\n", depth, file, line)
						}
					}
					if s, ok := rcv.(string); ok {
						msg = s
					}
					msg = fmt.Sprintf("%s\n%s", rcv.(error).Error(), stacktrace)
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

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "hidakkathon-go.session")
	return session
}

func setLogin(userId int) {
	inMemoryRedisMu.Lock()
	defer inMemoryRedisMu.Unlock()
	inMemoryRedis["login_"+strconv.Itoa(userId)] = time.Now().UnixNano() / int64(time.Millisecond)
}

func getLoginUsers() []int {
	var onLineUsers []int
	inMemoryRedisMu.Lock()
	defer inMemoryRedisMu.Unlock()
	for key, loginTime := range inMemoryRedis {
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
			return getUser(w, id)
		},
		"getIineCount": func(id int) int {
			return getIineCount(id)
		},
		"getTagCount": func(id int) int {
			return getTagCount(id)
		},
		"getArticle": func(id int) Article {
			return getArticle(w, id)
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
		"getCachedTagNames": func(m map[int][]TagName, key int) []TagName {
			x, ok := m[key]
			if ok {
				return x
			}
			return []TagName{}
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

	session := getSession(w, r)
	session.Values["user_id"] = userId
	session.Save(r, w)

	tx.Commit()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func GetPhoto(w http.ResponseWriter, r *http.Request) {
	memberID, _ := mux.Vars(r)["member_id"]
	if strings.HasSuffix(memberID, ".png") {
		memberID = memberID[:len(memberID)-4]
	}
	userId, err := strconv.Atoi(memberID)
	if err != nil {
		panic(memberID + " does not exist")
	}
	photoCacheMu.Lock()
	defer photoCacheMu.Unlock()

	body := photoCache[userId]
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

	maxPage := int(math.Ceil(float64(allArticleCount) / float64(pageSize)))

	rows, err := db.Query(`SELECT a.id, a.author_id, a.title, a.description, a.updated_at, a.created_at, COALESCE(u.id, 0), COALESCE(u.nick_name, ""), COALESCE(u.email, ""), COALESCE(u.passhash, "") FROM articles AS a LEFT JOIN users as u ON a.author_id = u.id ORDER BY a.created_at DESC, a.id DESC LIMIT ? OFFSET ?`, pageSize, offset)
	defer rows.Close()
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	articles := make([]Article, 0, pageSize)
	var articleDescription sql.NullString
	for rows.Next() {
		a := Article{}
		u := User{}
		if err := rows.Scan(&a.ID, &a.AuthorId, &a.Title, &articleDescription, &a.UpdatedAt, &a.CreatedAt, &u.ID, &u.NickName, &u.Email, &u.Passhash); err != nil {
			panic(err)
		}
		if articleDescription.Valid {
			a.Description = articleDescription.String
		}
		a.CachedAuthor = u
		articles = append(articles, a)
	}

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
	defer rows.Close()
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	tagNames := make([]TagName, 0, pageSize)
	var tagId int
	var name string
	var createdAt time.Time
	for rows.Next() {
		checkErr(rows.Scan(&tagId, &name, &createdAt))
		tagNames = append(tagNames, TagName{tagId, name, createdAt})
	}

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

	row := db.QueryRow("SELECT COUNT(*) as cnt FROM article_relate_tags WHERE tag_id = ?", tagId)
	var cnt int
	checkErr(row.Scan(&cnt))
	page, _ := strconv.Atoi(r.FormValue("page"))
	pageSize := 20

	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	maxPage := int(math.Ceil(float64(cnt) / float64(pageSize)))

	query := `SELECT
				COALESCE(a.id, 0), COALESCE(a.author_id, 0), COALESCE(a.title, ""), COALESCE(a.description, ""), a.updated_at, a.created_at
			FROM
				article_relate_tags AS ar
			LEFT JOIN articles AS a ON a.id = ar.article_id
			WHERE
				tag_id = ?
			ORDER BY
				article_id DESC
			LIMIT ? OFFSET ?`
	rows, err := db.Query(query, tagId, pageSize, offset)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	defer rows.Close()

	articleIDs := make([]interface{}, 0, pageSize)
	x := ""
	articleRelateTags := make([]Article, 0, pageSize)
	for rows.Next() {
		a := Article{}
		err = rows.Scan(&a.ID, &a.AuthorId, &a.Title, &a.Description, &a.UpdatedAt, &a.CreatedAt)
		checkErr(err)
		articleRelateTags = append(articleRelateTags, a)
		articleIDs = append(articleIDs, a.ID)

		if x == "" {
			x = "?"
		} else {
			x += ", ?"
		}
	}

	headerInfo.Current = ""
	headerInfo.Write = true

	query = fmt.Sprintf(`SELECT article_id, t.id, t.tagname FROM article_relate_tags AS ar LEFT JOIN tags AS t ON ar.tag_id = t.id WHERE article_id IN (%s) ORDER BY tag_id ASC`, x)
	rows2, err := db.Query(query, articleIDs...)
	defer rows2.Close()

	if err == sql.ErrNoRows {
		err = nil
	} else {
		checkErr(err)
	}

	var aid int
	tagNames := make(map[int][]TagName, 50) // articleID to tagname
	for rows2.Next() {
		t := TagName{}
		err := rows2.Scan(&aid, &t.ID, &t.Name)
		checkErr(err)
		_, ok := tagNames[aid]
		if ok {
			tagNames[aid] = append(tagNames[aid], t)
		} else {
			y := make([]TagName, 0, 50)
			y = append(y, t)
			tagNames[aid] = y
		}
	}

	for i := range articleRelateTags {
		a, ok := tagNames[articleRelateTags[i].ID]
		if ok {
			articleRelateTags[i].CachedTagNames = a
		} else {
			articleRelateTags[i].CachedTagNames = []TagName{}
		}
	}

	render(w, r, http.StatusOK, "tag.html", struct {
		User              User
		ArticleRelateTags []Article
		TagId             string
		Page              int
		MaxPage           int
		MaxCount          int
		HeaderInfo        HeaderInfo
		TagNames          map[int][]TagName
	}{
		*user,
		articleRelateTags,
		tagId,
		page,
		maxPage,
		cnt,
		headerInfo,
		tagNames,
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
	defer rows.Close()
	members := make([]User, 0, pageSize)
	for rows.Next() {
		var id int
		var nickName, email, passhash string
		checkErr(rows.Scan(&id, &nickName, &email, &passhash))
		members = append(members, User{id, nickName, email, passhash})
	}

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
	defer rows.Close()
	articles := make([]Article, 0, pageSize)
	for rows.Next() {
		var id, authorId int
		var title, description string
		var updatedAt, createdAt time.Time
		checkErr(rows.Scan(&id, &authorId, &title, &description, &updatedAt, &createdAt))
		articles = append(articles, Article{ID: id, AuthorId: authorId, Title: title, Description: description, UpdatedAt: updatedAt, CreatedAt: createdAt})
	}
	author := getUser(w, memberId)

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
	IineUsers := getArticleIineUsers(articleId)
	TagNames := getArticleTagNames(articleId)

	render(w, r, http.StatusOK, "article.html", struct {
		User       User
		ArticleId  int
		Article    Article
		DoneIine   int
		HeaderInfo HeaderInfo
		IineUsers  []int
		TagNames   []TagName
	}{
		*user,
		articleId,
		getArticle(w, articleId),
		cnt,
		headerInfo,
		IineUsers,
		TagNames,
	})
}

func PostIine(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	articleId, _ := strconv.Atoi(mux.Vars(r)["article_id"])
	sign := r.FormValue("name")

	var cnt int
	func() {
		var ok bool
		iineCountMu.Lock()
		defer iineCountMu.Unlock()
		cnt, ok = iineCount[articleId]
		if !ok {
			iineCount[articleId] = 0
		}
	}()

	var query string
	if sign == "plus" {
		query = "INSERT INTO iines (article_id, user_id) VALUES( ?, ? )"
		iineCount[articleId]++
	} else {
		query = "DELETE FROM iines WHERE article_id = ? AND user_id = ?"
		iineCount[articleId]--
	}
	db.Exec(query, articleId, user.ID)

	cachedPopularArticlesMu.Lock()
	defer cachedPopularArticlesMu.Unlock()
	if sign == "plus" {
		for i := range cachedPopularArticles {
			if cachedPopularArticles[i].ArticleId != articleId {
				continue
			}

			cachedPopularArticles[i].IineCnt++
			cachedPopularArticles[i].CachedIine = append(cachedPopularArticles[i].CachedIine, &Iine{
				ID:        0, // FIXME: use last insert id.
				ArticleId: articleId,
				UserId:    user.ID,
			})
			if i == 0 {
				break
			}

			for j := i; j > 0; j-- {
				if cachedPopularArticles[j-1].IineCnt > cachedPopularArticles[j].IineCnt {
					break
				} else if cachedPopularArticles[j-1].IineCnt == cachedPopularArticles[j].IineCnt && cachedPopularArticles[j-1].ArticleId > cachedPopularArticles[j].ArticleId {
					break
				}

				tmp := cachedPopularArticles[j]
				cachedPopularArticles[j-1] = cachedPopularArticles[j]
				cachedPopularArticles[j-1] = tmp
			}
			break
		}
	} else {
		for i := range cachedPopularArticles {
			if cachedPopularArticles[i].ArticleId != articleId {
				continue
			}

			cachedPopularArticles[i].IineCnt--
			for j := range cachedPopularArticles[i].CachedIine {
				if cachedPopularArticles[i].CachedIine[j].UserId == user.ID {
					cachedPopularArticles = append(cachedPopularArticles[:j-1], cachedPopularArticles[j:]...)
					break
				}
			}
		}
	}
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
	articleCountMu.Lock()
	defer articleCountMu.Unlock()
	articleCount[user.ID]++
	allArticleCountMu.Lock()
	defer allArticleCountMu.Unlock()
	allArticleCount++
	http.Redirect(w, r, "/article/"+articleId, http.StatusFound)
}

func GetUpdate(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)

	articleId, _ := strconv.Atoi(mux.Vars(r)["article_id"])
	article := getArticle(w, articleId)

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

	article := getArticle(w, articleId)

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
			Article{ID: articleId, AuthorId: article.AuthorId, Title: title, Description: articleBody, UpdatedAt: article.UpdatedAt, CreatedAt: article.CreatedAt},
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

	buf := new(bytes.Buffer)
	n, _ := buf.ReadFrom(iconFile)
	if n > 0 {
		insAndUpdUserPhoto(user.ID, buf.Bytes(), tx)
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
	inMemoryRedis = make(map[string]int64, 50)
	for i := 1; i < 500; i++ {
		setLogin(i)
	}
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		defer wg.Done()

		file, err := os.Open("./iine_count_cache.gob")
		if err != nil {
			panic(err)
		}
		defer file.Close()
		iineCountMu.Lock()
		defer iineCountMu.Unlock()

		err = gob.NewDecoder(file).Decode(&iineCount)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()

		tagArticleCountMu.Lock()
		defer tagArticleCountMu.Unlock()
		file, err := os.Open("./tag_article_count_cache.gob")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		err = gob.NewDecoder(file).Decode(&tagArticleCount)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()

		articleCountMu.Lock()
		defer articleCountMu.Unlock()
		file, err := os.Open("./article_count_cache.gob")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		err = gob.NewDecoder(file).Decode(&articleCount)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()
		cachedPopularArticlesMu.Lock()
		defer cachedPopularArticlesMu.Unlock()
		file, err := os.Open("./popular_articles.gob")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		err = gob.NewDecoder(file).Decode(&cachedPopularArticles)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()

		allArticleCountMu.Lock()
		defer allArticleCountMu.Unlock()
		row := db.QueryRow("SELECT COUNT(*) as cnt FROM articles")
		checkErr(row.Scan(&allArticleCount))
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()

		articleCountMu.Lock()
		defer articleCountMu.Unlock()
		file, err := os.Open("./photo_cache.gob")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		err = gob.NewDecoder(file).Decode(&photoCache)
		if err != nil {
			panic(err)
		}
	}()
	wg.Wait()
}

func main() {
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

	inMemoryRedis = make(map[string]int64, 50)
	db, _ = sql.Open("mysql", fmt.Sprintf("%s:%s@unix(/var/run/mysqld/mysqld.sock)/%s?loc=Local&parseTime=true", user, password, dbname))
	defer db.Close()

	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(24)
	db.SetConnMaxLifetime(24 * time.Second)

	store = sessions.NewCookieStore([]byte(ssecret))

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
	runtime.SetBlockProfileRate(1)
	initStaticFiles(r, "../static")
	GetInitialize(nil, nil)
}

func initStaticFiles(r *mux.Router, prefix string) {
	wf := func(path string, info os.FileInfo, err error) error {
		if path == prefix {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".png") {
			return nil
		}
		urlpath := path[len(prefix):]
		if urlpath[0] != '/' {
			urlpath = "/" + urlpath
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}

		var contentType string
		if strings.HasSuffix(path, ".css") {
			contentType = "text/css"
		} else if strings.HasSuffix(path, ".js") {
			contentType = "application/javascript"
		} else if strings.HasSuffix(path, ".woff") {
			contentType = "application/font-woff"
		} else if strings.HasSuffix(path, ".ttf") {
			contentType = "application/x-font-ttf"
		} else if strings.HasSuffix(path, ".otf") {
			contentType = "application/x-font-otf"
		} else if strings.HasSuffix(path, ".svg") {
			contentType = "image/svg+xml"
		} else if strings.HasSuffix(path, ".eot") {
			contentType = "image/vnd.ms-fontobject"
		}
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
			w.Write(data)
		}
		r.Path(urlpath).Methods("Get").HandlerFunc(handler)
		return nil
	}
	filepath.Walk("../static", wf)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
