.PHONY: build test lint dist clean

build:
	go build -o bin/export-tool .

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

dist:
	./scripts/build-release.sh

clean:
	rm -rf bin dist
