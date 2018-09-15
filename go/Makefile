all: app
deps:
	go get github.com/go-sql-driver/mysql
	go get github.com/gomodule/redigo/redis
	go get github.com/gorilla/context
	go get github.com/gorilla/mux
	go get github.com/gorilla/sessions
build: deps
	go build -o app app.go
run:
	./app
.PHONY: all deps
