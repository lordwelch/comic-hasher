package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
)

func main() {
	inPath := flag.String("in", "", "path to the old saved hashes file (hashes.gz)")
	outPath := flag.String("out", "", "path to write the converted V3 hashes file (hashes.gz)")
	var logLevels log.Flag
	flag.Var(&logLevels, "log-level", "Change logging level\nAvailable Loggers: "+strings.Join([]string(log.AvailableLoggers()), ", ")+"\nAvailable Aliases: "+strings.Join(log.Aliases(), ", "))

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
	if err == nil {
		err = convertV2(hashes, inPath)
		if err != nil {
			return fmt.Errorf("failed to decode old hashes %q: %w", inPath, err)
		}
		return nil
	}
	if inPath == outPath {
		return fmt.Errorf("unable to merge 1 file into itself")
	}
	V3Hashes, err := ch.DecodeHashesV3(bytes.NewReader(hashesBytes))
	if err != nil {
		return fmt.Errorf("failed to read any hashes %q: %w", inPath, err)
	}

	V3Hashes.LogHashInfo(log.Standard, "in file")

	data, err = os.ReadFile(outPath)
	if err != nil {
		return fmt.Errorf("failed to read V3 hashes for merging %q: %w", outPath, err)
	}
	hashesBytes, err = decompressIfGzipped(data)
	if err != nil {
		return fmt.Errorf("failed to decompress V3 hashes for merging %q: %w", outPath, err)
	}
	V3ExistingHashes, err := ch.DecodeHashesV3(bytes.NewReader(hashesBytes))
	if err != nil {
		return fmt.Errorf("failed to read existing V3 hashes for merging %q: %w", inPath, err)
	}
	V3ExistingHashes.LogHashInfo(log.Standard, "out file")
	err = V3ExistingHashes.Merge(V3Hashes)
	if err != nil {
		return fmt.Errorf("failed to merge %s into %s: %w", inPath, outPath, err)
	}
	err = writeV3Hashes(V3ExistingHashes, outPath)
	if err != nil {
		return err
	}

	return nil
}

func writeV3Hashes(hashes *ch.SavedHashesV3, path string) error {
	hashes.LogHashInfo(log.Standard, "final file")
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	err := ch.EncodeHashesV3(hashes, gzw)
	if err != nil {
		return fmt.Errorf("failed to encode V3 hashes: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return fmt.Errorf("failed to close gzip output: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write output hashes %q: %w", path, err)
	}
	return nil
}

func convertV2(hashes *ch.SavedHashesV2, outPath string) error {
	DELogger.Println(log.Standard, "Decoded old hashes with", log.FormatInt(len(hashes.Hashes)), "hashes and", log.FormatInt(len(hashes.IDs)), "ID groups")

	v3Hashes, err := ch.NewSavedHashesV3(hashes)
	if err != nil {
		return fmt.Errorf("failed to convert old hashes: %w", err)
	}
	err = writeV3Hashes(v3Hashes, outPath)
	if err != nil {
		return err
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
