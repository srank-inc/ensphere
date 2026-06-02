BINARY_NAME = ensphere
SEEDS_DIR   = ./assets/seeds
DB_PATH     = ./cli/internal/payloads/payloads.sqlite
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build seeds checklists verify-generated clean install install-all test smoke

build: seeds checklists
	cd cli && go build -ldflags "-X github.com/srank/ensphere/cmd.version=$(VERSION)" -o ../bin/$(BINARY_NAME) .

seeds:
	cd cli && go run ./tools/seedgen ../$(SEEDS_DIR) ./internal/payloads/payloads.sqlite

checklists:
	rm -rf cli/internal/checklist/data
	@mkdir -p cli/internal/checklist/data
	cp skills/checklists/*.md cli/internal/checklist/data/

verify-generated: seeds checklists
	@git ls-files --error-unmatch cli/internal/payloads/payloads.sqlite >/dev/null 2>&1 || (echo "generated asset is not tracked: cli/internal/payloads/payloads.sqlite"; exit 1)
	git diff --exit-code -- cli/internal/payloads/payloads.sqlite cli/internal/checklist/data
	@test -z "$$(git ls-files --others --exclude-standard -- cli/internal/payloads/payloads.sqlite cli/internal/checklist/data)" || (echo "untracked generated assets:"; git ls-files --others --exclude-standard -- cli/internal/payloads/payloads.sqlite cli/internal/checklist/data; exit 1)

install: build
	cp bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

install-all: install
	./install-skills.sh

clean:
	rm -rf bin/
	rm -f cli/$(BINARY_NAME)
	rm -rf cli/.gocache/
	rm -f evidence.jsonl evidence.jsonl.lock
	rm -rf ensphere-pentest/

test:
	cd cli && go vet ./...
	cd cli && go test ./...

smoke: build
	./bin/$(BINARY_NAME) --version >/dev/null
	./bin/$(BINARY_NAME) payloads sqli --db postgres --technique blind_time --limit 1 >/dev/null
	./bin/$(BINARY_NAME) payloads sqli --db sqlite --technique blind_boolean --limit 1 >/dev/null
	./bin/$(BINARY_NAME) template --list >/dev/null
	./bin/$(BINARY_NAME) checklist --list >/dev/null
	./bin/$(BINARY_NAME) compliance --list >/dev/null
	./bin/$(BINARY_NAME) cvss --version 3.1 --av N --ac L --pr N --ui N --s U --c H --i H --a H >/dev/null
	@echo "smoke ok"
