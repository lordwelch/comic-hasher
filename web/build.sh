#!/bin/sh
# Builds the wasm hashing module and copies the Go wasm loader into web/static.
set -eu

cd "$(dirname "$0")/.."

GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/static/main.wasm ./web/wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/static/wasm_exec.js
