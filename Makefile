BINARY := agent-db-scan
CMD    := ./cmd/agent-db-scan
PKG    := ./...

.PHONY: build test lint tidy run docker-up docker-down clean

build:
	go build -o bin/$(BINARY) $(CMD)

test:
	go test -race -cover $(PKG)

lint:
	golangci-lint run

tidy:
	go mod tidy

run: build
	./bin/$(BINARY)

# Integration test fixture (see docker-compose.yml, testdata/schema.sql).
docker-up:
	docker compose up -d

docker-down:
	docker compose down -v

clean:
	rm -rf bin
