package main

import (
	"crypto"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"

	"github.com/OneOfOne/xxhash"
	"github.com/twmb/murmur3"
	"github.com/zeebo/xxh3"
)

var digesters = map[string]hash.Hash{
	"sha":                       crypto.SHA1.New(),
	crypto.SHA1.String():        crypto.SHA1.New(),
	crypto.SHA256.String():      crypto.SHA256.New(),
	crypto.MD5.String():         crypto.MD5.New(),
	"XXH3":                      xxh3.New(),
	"adler":                     adler32.New(),
	"crc32c":                    crc32.NewIEEE(),
	"fnv1-32":                   fnv.New32(),
	"fnv1a-32":                  fnv.New32a(),
	"fnv1-64":                   fnv.New64(),
	"fnv1a-64":                  fnv.New64a(),
	"fnv1-128":                  fnv.New128(),
	"fnv1a-128":                 fnv.New128a(),
	crypto.SHA224.String():      crypto.SHA224.New(),
	crypto.SHA384.String():      crypto.SHA384.New(),
	crypto.SHA512.String():      crypto.SHA512.New(),
	crypto.SHA3_224.String():    crypto.SHA3_224.New(),
	crypto.SHA3_256.String():    crypto.SHA3_256.New(),
	crypto.SHA3_384.String():    crypto.SHA3_384.New(),
	crypto.SHA3_512.String():    crypto.SHA3_512.New(),
	crypto.SHA512_224.String():  crypto.SHA512_224.New(),
	crypto.SHA512_256.String():  crypto.SHA512_256.New(),
	crypto.BLAKE2s_256.String(): crypto.BLAKE2s_256.New(),
	crypto.BLAKE2b_256.String(): crypto.BLAKE2b_256.New(),
	crypto.BLAKE2b_384.String(): crypto.BLAKE2b_384.New(),
	crypto.BLAKE2b_512.String(): crypto.BLAKE2b_512.New(),
	"XXH64":                     xxhash.New64(),
	"XXH32":                     xxhash.New32(),
	"XXH128":                    xxh3.New128(),
	"murmur3-32":                murmur3.New32(),
	"murmur3-64":                murmur3.New64(),
	"murmur3-128":               murmur3.New128(),
}

var hashNames = []string{
	"XXH128",
	"XXH3",
	"XXH64",
	"XXH32",
	"sha",
	crypto.SHA1.String(),
	crypto.SHA256.String(),
	crypto.MD5.String(),
	"murmur3-32",
	"murmur3-64",
	"murmur3-128",
	"adler",
	"fnv1-32",
	"fnv1a-32",
	"fnv1-64",
	"fnv1a-64",
	"fnv1-128",
	"fnv1a-128",
	crypto.SHA224.String(),
	crypto.SHA384.String(),
	crypto.SHA512.String(),
	crypto.SHA3_224.String(),
	crypto.SHA3_256.String(),
	crypto.SHA3_384.String(),
	crypto.SHA3_512.String(),
	crypto.SHA512_224.String(),
	crypto.SHA512_256.String(),
	crypto.BLAKE2s_256.String(),
	crypto.BLAKE2b_256.String(),
	crypto.BLAKE2b_384.String(),
	crypto.BLAKE2b_512.String(),
	"crc32c",
}
