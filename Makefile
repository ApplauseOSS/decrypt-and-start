BINARY=decrypt-and-start

# Determine root directory
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Gather all .go files for use in dependencies below
GO_FILES=$(shell find $(ROOT_DIR) -name '*.go')

# Build our program binary
# Depends on GO_FILES to determine when rebuild is needed
$(BINARY): mod-tidy $(GO_FILES)
	go build -ldflags="-s -w" -o $(BINARY) $(ROOT_DIR)

.PHONY: build clean

# Alias for building program binary
build: $(BINARY)

mod-tidy:
	# Needed to fetch new dependencies and add them to go.mod
	go mod tidy

clean:
	rm -f $(BINARY)

format: mod-tidy
	go fmt ./...
	gofmt -s -w $(GO_FILES)

golines:
	golines -w --ignore-generated --chain-split-dots --max-len=80 --reformat-tags .

test: mod-tidy
	go test -v -race ./...
