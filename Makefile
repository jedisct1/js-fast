.PHONY: all build build-js build-types test lint clean

all: build

build: build-js build-types

build-js:
	bun build ./src/index.ts --outfile dist/index.js --target node
	bun build ./src/tokens/index.ts --outfile dist/tokens/index.js --target node

build-types:
	bunx tsc -p tsconfig.build.json

test:
	bun test

lint:
	bunx tsc --noEmit

clean:
	rm -rf dist
