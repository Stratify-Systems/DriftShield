.PHONY: build clean run install

build:
	go build -o driftshield ./cmd/driftshield

clean:
	rm -f driftshield

run:
	go run ./cmd/driftshield

install:
	go install ./cmd/driftshield

tidy:
	go mod tidy

test:
	go test -v ./...
