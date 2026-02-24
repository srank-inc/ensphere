BINARY_NAME = ensphere
SEEDS_DIR   = ./assets/seeds
DB_PATH     = ./cli/internal/payloads/payloads.sqlite

.PHONY: build seeds checklists clean install install-all test

build: seeds checklists
	cd cli && go build -o ../bin/$(BINARY_NAME) .

seeds:
	cd cli && go run ./tools/seedgen ../$(SEEDS_DIR) ./internal/payloads/payloads.sqlite

checklists:
	@mkdir -p cli/internal/checklist/data
	cp skills/checklists/*.md cli/internal/checklist/data/

install: build
	cp bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

install-all: install
	./install-skills.sh

clean:
	rm -rf bin/
	rm -f $(DB_PATH)
	rm -rf cli/internal/checklist/data/

test:
	cd cli && go vet ./...
	cd cli && go test ./...
