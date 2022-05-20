VERSION = "0.0.1"
change-gorilla-version:
	@echo "package gorilla\n\n// Version constant of gorilla\nconst Version = \"$(VERSION)\"">gorilla/capability/gorilla/version.go
	@git add gorilla/capability/gorilla/version.go
	@git commit -m "gorilla/v$(VERSION)"
	@git tag -a "gorilla/v$(VERSION)" -m "gorilla/v$(VERSION)"
	@git push origin
	@git push origin "gorilla/v$(VERSION)"

test:
	go test -count=1 -race ./... -v

bench:
	go test -count=1 -race ./... -v -bench=. -benchtime=5s

update-module:
	go env -w GOPRIVATE=github.com/mkawserm
	go get -v github.com/mkawserm/abesh

install-swag:
	go install github.com/swaggo/swag/cmd/swag@latest

swag-init:
	swag init -g=swagger.go
