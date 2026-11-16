#!/bin/sh
# Builds the wasm hashing module and copies the Go wasm loader into web/static.
set -eu

cd "$(dirname "$0")/.."
rm -f web/static/main.wasm{,.br}
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/static/main.wasm ./web/wasm
if [ -z "${1+x}" ]; then
	brotli web/static/main.wasm
else
	brotli -0 web/static/main.wasm
fi
mv web/static/main.wasm{.br,}
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/static/wasm_exec.js
