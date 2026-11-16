//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"path"
	"slices"
	"strings"
	"syscall/js"
	"time"

	"gitea.narnian.us/lordwelch/goimagehash"
	_ "github.com/gen2brain/gav1d/avif"
	_ "github.com/gen2brain/jxl"
	_ "github.com/spakin/netpbm"
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"
)

var imageExts = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".webp": true,
	".bmp":  true,
	".tif":  true,
	".tiff": true,
}

func main() {
	js.Global().Set("hashCover", js.FuncOf(hashCoverJS))
	select {}
}

// hashCoverJS is called as hashCover(name, bytes) and returns either
// {error} or {entry, format, width, height, ahash, dhash, phash}.
func logTiming(label string, d time.Duration) {
	fmt.Printf("[timing] %s: %.1f ms\n", label, float64(d.Microseconds())/1000)
}

// inputBuf is reused across calls so small files don't allocate a new copy.
// Files larger than maxInputBufSize use a temporary buffer so inputBuf stays bounded.
const maxInputBufSize = 5 * 1024 * 1024

var inputBuf []byte

func hashCoverJS(this js.Value, args []js.Value) any {
	if len(args) != 2 {
		return map[string]any{"error": "hashCover expects (name, bytes)"}
	}
	start := time.Now()
	name := args[0].String()
	n := args[1].Get("byteLength").Int()
	var data []byte
	if n <= maxInputBufSize {
		if cap(inputBuf) < n {
			inputBuf = make([]byte, n)
		}
		data = inputBuf[:n]
	} else {
		data = make([]byte, n)
	}
	js.CopyBytesToGo(data, args[1])
	logTiming("wasm copy "+name, time.Since(start))

	res, err := hashFile(name, data)
	logTiming("wasm hashCover "+name, time.Since(start))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return res
}

func hashFile(name string, data []byte) (map[string]any, error) {
	var (
		entry   string
		im      image.Image
		format  string
		err     error
		imBytes js.Value
	)
	start := time.Now()
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		entry, im, format, imBytes, err = coverFromZip(data)
	case bytes.HasPrefix(data, []byte("Rar!\x1a\x07")):
		return nil, errors.New("RAR archives are not supported by this build, convert to CBZ/ZIP")
	default:
		entry = name
		im, format, err = decodeImage(data)
		if format == "ppm" {
			b := bytes.NewBuffer(nil)
			jpeg.Encode(b, im, nil)
			imBytes = js.Global().Get("Uint8Array").New(b.Len())
			// 2. Copy the bytes from Go into the JS Uint8Array
			js.CopyBytesToJS(imBytes, b.Bytes())
		}
	}
	if err != nil {
		return nil, err
	}

	logTiming("wasm decode "+name, time.Since(start))

	if format == "webp" {
		upscaleStart := time.Now()
		if ycbcr, ok := im.(*image.YCbCr); ok {
			im = goimagehash.FancyUpscale(ycbcr)
		}
		logTiming("wasm webp upscale "+name, time.Since(upscaleStart))
	}
	grayStart := time.Now()
	im = goimagehash.ToGray(im, nil)
	logTiming("wasm ToGray ", time.Since(grayStart))

	hashStart := time.Now()
	ahash, err := goimagehash.AverageHash(im)
	if err != nil {
		return nil, fmt.Errorf("failed to ahash image: %w", err)
	}
	logTiming("wasm ahash "+name, time.Since(hashStart))
	hashStart = time.Now()
	dhash, err := goimagehash.DifferenceHash(im)
	if err != nil {
		return nil, fmt.Errorf("failed to dhash image: %w", err)
	}
	logTiming("wasm dhash "+name, time.Since(hashStart))
	hashStart = time.Now()
	phash, err := goimagehash.PerceptionHash(im)
	if err != nil {
		return nil, fmt.Errorf("failed to phash image: %w", err)
	}
	logTiming("wasm phash "+name, time.Since(hashStart))
	bounds := im.Bounds()

	return map[string]any{
		"entry":  entry,
		"format": format,
		"width":  bounds.Dx(),
		"height": bounds.Dy(),
		"ahash":  fmt.Sprintf("%016x", ahash.GetHash()),
		"dhash":  fmt.Sprintf("%016x", dhash.GetHash()),
		"phash":  fmt.Sprintf("%016x", phash.GetHash()),
		"image":  imBytes,
	}, nil
}

func decodeImage(data []byte) (image.Image, string, error) {
	im, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode image: %w", err)
	}
	return im, format, nil
}

// coverFromZip returns the first image in natural name order that decodes.
func coverFromZip(data []byte) (string, image.Image, string, js.Value, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", nil, "", js.Null(), fmt.Errorf("failed to read zip: %w", err)
	}
	var candidates []*zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !isImageName(f.Name) {
			continue
		}
		candidates = append(candidates, f)
	}
	if len(candidates) == 0 {
		return "", nil, "", js.Null(), errors.New("no images found in archive")
	}
	slices.SortFunc(candidates, func(a, b *zip.File) int {
		if naturalLess(a.Name, b.Name) {
			return -1
		}
		if naturalLess(b.Name, a.Name) {
			return 1
		}
		return 0
	})
	var lastErr error
	for _, f := range candidates {
		b, err := readZipFile(f)
		if err != nil {
			lastErr = err
			continue
		}
		im, format, err := decodeImage(b)
		if err != nil {
			lastErr = err
			continue
		}
		uint8Array := js.Global().Get("Uint8Array").New(len(b))
		// 2. Copy the bytes from Go into the JS Uint8Array
		js.CopyBytesToJS(uint8Array, b)
		return f.Name, im, format, uint8Array, nil
	}
	return "", nil, "", js.Null(), fmt.Errorf("no decodable images in archive: %w", lastErr)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func isImageName(name string) bool {
	for part := range strings.SplitSeq(name, "/") {
		if part == "__MACOSX" || strings.HasPrefix(part, ".") {
			return false
		}
	}
	return imageExts[strings.ToLower(path.Ext(name))]
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// chunk splits s into a leading run of digits or non-digits.
func chunk(s string) (string, string) {
	i := 1
	for i < len(s) && isDigit(s[i]) == isDigit(s[0]) {
		i++
	}
	return s[:i], s[i:]
}

func naturalLess(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	for a != "" && b != "" {
		var x, y string
		x, a = chunk(a)
		y, b = chunk(b)
		if isDigit(x[0]) && isDigit(y[0]) {
			xt, yt := strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(xt) != len(yt) {
				return len(xt) < len(yt)
			}
			if xt != yt {
				return xt < yt
			}
			continue
		}
		if x != y {
			return x < y
		}
	}
	return len(a) < len(b)
}
