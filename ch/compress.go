package ch

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/klauspost/compress/zstd"
	minlz "github.com/minio/minlz"
)

// Compression is the algorithm used to compress cached entries.
type Compression uint8

const (
	// CompressionMinLZ compresses with github.com/minio/minlz.
	CompressionMinLZ Compression = iota
	// CompressionZSTD compresses with github.com/klauspost/compress/zstd.
	CompressionZSTD
)

var compressionNames = map[Compression]string{
	CompressionMinLZ: "minlz",
	CompressionZSTD:  "zstd",
}

var compressionValues = map[string]Compression{
	"minlz": CompressionMinLZ,
	"zstd":  CompressionZSTD,
}

func (c Compression) String() string {
	if name, ok := compressionNames[c]; ok {
		return name
	}
	return "unknown"
}

// Set implements flag.Value.
func (c *Compression) Set(s string) error {
	compression, ok := compressionValues[strings.ToLower(s)]
	if !ok {
		return fmt.Errorf("unknown compression %q, must be one of %s", s, strings.Join(compressionOptions(), ", "))
	}
	*c = compression
	return nil
}

func compressionOptions() []string {
	options := make([]string, 0, len(compressionValues))
	for option := range compressionValues {
		options = append(options, option)
	}
	return options
}

// Codec compresses and decompresses cache entries with a Compression
// algorithm. The zero value uses MinLZ without a dictionary.
type Codec struct {
	Compression Compression

	zstd *zstdCodec
}

// NewCodec returns a Codec for compression. When compression is
// CompressionZSTD, dict may contain a zstd dictionary to use.
func NewCodec(compression Compression, dict []byte) (Codec, error) {
	codec := Codec{Compression: compression}
	switch compression {
	case CompressionMinLZ:
	case CompressionZSTD:
		zstdCodec, err := newZstdCodec(dict)
		if err != nil {
			return Codec{}, err
		}
		codec.zstd = zstdCodec
	default:
		return Codec{}, fmt.Errorf("unknown compression %d", compression)
	}
	return codec, nil
}

// Compress returns src compressed with the codec's algorithm.
func (c Codec) Compress(src []byte) ([]byte, error) {
	if c.Compression == CompressionZSTD {
		if c.zstd == nil {
			return nil, fmt.Errorf("zstd codec is not configured")
		}
		return c.zstd.encoder.EncodeAll(src, nil), nil
	}
	return minlz.AppendEncoded(nil, src, minlz.LevelFastest)
}

// Decompress appends the decoded data to dst and returns it. Data that isn't
// compressed, such as the raw text stored before compression was added, is
// returned unchanged. Compressed data that can't be decoded is also returned
// unchanged.
func (c Codec) Decompress(dst, src []byte) []byte {
	if bytes.HasPrefix(src, zstdMagic) {
		if c.zstd == nil {
			return src
		}
		decoded, err := c.zstd.decoder.DecodeAll(src, dst)
		if err != nil {
			return src
		}
		return decoded
	}
	return decompressMinLZ(dst, src)
}

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

type zstdCodec struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

// newZstdCodec creates the shared encoder and decoder used by a Codec. A nil
// dict creates a dictionary-less codec.
func newZstdCodec(dict []byte) (*zstdCodec, error) {
	encoderOptions := []zstd.EOption{
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1),
	}
	if len(dict) > 0 {
		encoderOptions = append(encoderOptions, zstd.WithEncoderDict(dict))
	}
	encoder, err := zstd.NewWriter(nil, encoderOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	decoderOptions := []zstd.DOption{
		zstd.WithDecoderConcurrency(1),
	}
	if len(dict) > 0 {
		decoderOptions = append(decoderOptions, zstd.WithDecoderDicts(dict))
	}
	decoder, err := zstd.NewReader(nil, decoderOptions...)
	if err != nil {
		encoder.Close()
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}
	return &zstdCodec{encoder: encoder, decoder: decoder}, nil
}

// DecompressMinLZ returns the decoded data if src is minlz encoded.
// Data that is not minlz encoded, such as the raw text stored before
// compression was added, is returned unchanged.
func DecompressMinLZ(src []byte) []byte {
	return decompressMinLZ(nil, src)
}

func decompressMinLZ(dst, src []byte) []byte {
	ok, _, err := minlz.IsMinLZ(src)
	if err != nil || !ok {
		return src
	}
	decoded, err := minlz.Decode(dst, src)
	if err != nil {
		return src
	}
	return decoded
}
