.PHONY: build test verify-mod verify-reproducible clean

build:
	go build -trimpath -ldflags="-buildid= -s -w" -o ./bin/zerotrust .

test:
	go test -v -race ./...

verify-mod:
	go mod tidy
	go mod verify

verify-reproducible:
	go build -trimpath -ldflags="-buildid= -s -w" -o ./bin/repro_1/zerotrust .
	go build -trimpath -ldflags="-buildid= -s -w" -o ./bin/repro_2/zerotrust .
	@go run ./cmd/verify_repro

clean:
	go clean
