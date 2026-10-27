package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
)

func main() {
	inPath := flag.String("in", "", "path to the old saved hashes file (hashes.gz)")
	outPath := flag.String("out", "", "path to write the converted V3 hashes file (hashes.gz)")
	flag.Parse()
	if *inPath == "" || *outPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*inPath, *outPath); err != nil {
		log.Println(log.Fatal, "Failed to convert hashes:", err)
		os.Exit(1)
	}
}

func run(inPath, outPath string) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("failed to read input hashes %q: %w", inPath, err)
	}
	hashesBytes, err := decompressIfGzipped(data)
	if err != nil {
		return fmt.Errorf("failed to decompress input hashes %q: %w", inPath, err)
	}
	hashes, err := DecodeOldHashes(hashesBytes)
	if err != nil {
		return fmt.Errorf("failed to decode old hashes %q: %w", inPath, err)
	}
	DELogger.Println(log.Standard, "Decoded old hashes with", len(hashes.Hashes), "hashes and", len(hashes.IDs), "id groups")

	v3Hashes, err := ch.NewSavedHashesV3(hashes)
	if err != nil {
		return fmt.Errorf("failed to convert old hashes %q: %w", inPath, err)
	}

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	err = ch.EncodeHashesV3(v3Hashes, gzw)
	if err != nil {
		return fmt.Errorf("failed to encode V3 hashes: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return fmt.Errorf("failed to close gzip output: %w", err)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write output hashes %q: %w", outPath, err)
	}
	DELogger.Println(log.Standard, "Converted old hashes to V3 format and wrote", outPath)
	return nil
}

// decompressIfGzipped returns the decompressed bytes when the input starts
// with the gzip magic bytes, otherwise it returns the input unchanged.
func decompressIfGzipped(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	out, err := io.ReadAll(gzr)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip data: %w", err)
	}
	return out, nil
}
