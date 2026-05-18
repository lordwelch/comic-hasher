package main

import (
	"bufio"
	"cmp"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
	"image"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/twmb/murmur3"
	"github.com/zeebo/xxh3"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"

	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
)

type Server struct {
	httpServer     *http.Server
	mux            *CHMux
	BaseURL        *url.URL
	hashes         ch.HashStorage
	hashServer     HashServer
	Context        context.Context
	cancel         func()
	signalQueue    chan os.Signal
	readerQueue    chan string
	hashingQueue   chan ch.Im
	mappingQueue   chan ch.ImageHash
	onlyHashNewIDs bool
	version        string
}

type HashServer struct {
	hashes            string
	mut               sync.RWMutex
	digests           map[string][]byte
	digestHeaderCache string
	format            ch.Format
	digesters         map[string]hash.Hash
}

type CHMux struct {
	version string
	*http.ServeMux
}

func (CHM *CHMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Comic-Hasher "+CHM.version)
	CHM.ServeMux.ServeHTTP(w, r)
}

func (s *Server) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	return strings.TrimSpace("lordwelch"), true
}

func (s *Server) setupAppHandlers() {
	s.mux.HandleFunc("/add_cover", s.addCover)
	s.mux.HandleFunc("/match_cover_hash", s.matchCoverHash)
	s.mux.HandleFunc("/associate_ids", s.associateIDs)
	s.mux.HandleFunc("/hashes", s.hashServer.downloadHashes)
}

func (h *HashServer) downloadHashes(w http.ResponseWriter, r *http.Request) {
	h.mut.RLock()
	defer h.mut.RUnlock()
	if r.Header.Get("Want-Digest") != "" {
		w.Header().Set("Digest", h.digestHeader())
	}
	w.Header().Set("Repr-Digest", h.reprDigestHeader())
	w.Header().Set("Content-Type", "application/x-image-hash-db+"+h.format.String())
	w.Header().Set("Content-Disposition", `"attachment; filename="hashes.gz"`)
	http.ServeFile(w, r, h.hashes)
}

func (h *HashServer) reprDigestHeader() string {
	if h.digestHeaderCache != "" {
		return h.digestHeaderCache
	}
	s := &strings.Builder{}
	if len(h.digests) == 0 {
		return ""
	}
	for digestName, digest := range h.digests {
		s.WriteString(digestName)
		s.WriteString("=:")
		enc := base64.NewEncoder(base64.StdEncoding, s)
		_, _ = enc.Write(digest)
		_ = enc.Close()
		s.WriteString(":,")
	}
	str := s.String()
	return str[:len(str)-1]
}

func (h *HashServer) digestHeader() string {
	s := &strings.Builder{}
	if len(h.digests) == 0 {
		return ""
	}
	for digestName, digest := range h.digests {
		s.WriteString(digestName)
		s.WriteString("=")
		enc := base64.NewEncoder(base64.StdEncoding, s)
		_, _ = enc.Write(digest)
		_ = enc.Close()
		s.WriteString(",")
	}
	str := s.String()
	return str[:len(str)-1]
}

func (h *HashServer) writeHashes(hashes ch.HashStorage) error {
	// Encoding hashes requires a lock as it assumes pointers are in use to reduce unnecessary memory usage
	hashes.RLock()
	defer hashes.RUnlock()
	encodedHashes, err := hashes.EncodeHashes()
	if err != nil {
		return err
	}
	content, err := ch.EncodeHashes(encodedHashes, h.format)
	if err != nil {
		return err
	}
	f, err := os.Create(h.hashes + ".tmp")
	if err != nil {
		return fmt.Errorf("failed to write hashes to temporary file %q, %w", h.hashes+".tmp", err)
	}
	defer f.Close() //nolint:errcheck
	writer := h.initDigests(f)
	_, err = writer.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write hashes to temporary file %q, %w", h.hashes+".tmp", err)
	}
	h.mut.Lock()
	defer h.mut.Unlock()
	h.digestHeaderCache = ""
	// Explicit close. Windows has issues with operating on open files
	_ = f.Close()
	for name, digest := range h.digesters {
		h.digests[name] = digest.Sum(nil)
		digest.Reset() // may possibly keep some memory free...
	}
	err = os.Rename(h.hashes+".tmp", h.hashes)
	if err != nil {
		return fmt.Errorf("failed to update existing file%w", err)
	}
	return nil
}

func NewHashServer(hashes string, format ch.Format) HashServer {
	h := HashServer{
		hashes:  hashes,
		format:  format,
		digests: map[string][]byte{},
	}
	f, err := os.Open(hashes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return h //nolint:govet
		}
		panic(fmt.Errorf("unable to open the hashes file %q: %w", hashes, err))
	}
	defer f.Close() //nolint:errcheck
	writer := h.initDigests(io.Discard)
	_, err = io.Copy(writer, f)
	if err != nil {
		panic(fmt.Errorf("checksum hashes file %q, %w", h.hashes, err))
	}
	for name, digest := range h.digesters {
		h.digests[name] = digest.Sum(nil)
		digest.Reset() // may possibly keep some memory free...
	}

	return h //nolint:govet
}

func (h *HashServer) initDigests(writer io.Writer) io.Writer {
	if h.digesters == nil {
		h.digesters = map[string]hash.Hash{
			"sha":                       crypto.SHA1.New(),
			"adler":                     adler32.New(),
			"crc32c":                    crc32.NewIEEE(),
			"fnv1-32":                   fnv.New32(),
			"fnv1a-32":                  fnv.New32a(),
			"fnv1-64":                   fnv.New64(),
			"fnv1a-64":                  fnv.New64a(),
			"fnv1-128":                  fnv.New128(),
			"fnv1a-128":                 fnv.New128a(),
			crypto.MD5.String():         crypto.MD5.New(),
			crypto.SHA1.String():        crypto.SHA1.New(),
			crypto.SHA224.String():      crypto.SHA224.New(),
			crypto.SHA256.String():      crypto.SHA256.New(),
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
			"XXH3":                      xxh3.New(),
			"XXH128":                    xxh3.New128(),
			"murmur3-32":                murmur3.New32(),
			"murmur3-64":                murmur3.New64(),
			"murmur3-128":               murmur3.New128(),
		}
	}
	writers := make([]io.Writer, 0, len(h.digesters)+1)
	writers = append(writers, writer)
	for _, digest := range h.digesters {
		digest.Reset()
		writers = append(writers, digest)
	}
	return io.MultiWriter(writers...)
}

func (s *Server) associateIDs(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	var (
		values    = r.URL.Query()
		domain    = ch.Source(strings.ToLower(strings.TrimSpace(values.Get("domain"))))
		ID        = strings.ToLower(strings.TrimSpace(values.Get("id")))
		newDomain = ch.Source(strings.ToLower(strings.TrimSpace(values.Get("newDomain"))))
		newID     = strings.ToLower(strings.TrimSpace(values.Get("newID")))
	)
	if ID == "" {
		msg := "No ID Provided"
		log.Println(msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if domain == "" {
		msg := "No domain Provided"
		log.Println(msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newID == "" {
		msg := "No newID Provided"
		log.Println(msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newDomain == "" {
		msg := "No newDomain Provided"
		log.Println(msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newDomain == domain {
		msg := "newDomain cannot be the same as the existing domain"
		log.Println(msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	log.Printf("Attempting to associate %s:%s to %s:%s", domain, ID, newDomain, newID)
	err := s.hashes.AssociateIDs([]ch.NewIDs{{
		OldID: ch.ID{
			Domain: &domain,
			ID:     ID,
		},
		NewID: ch.ID{
			Domain: &newDomain,
			ID:     newID,
		},
	}})

	if err == nil {
		writeJSON(w, http.StatusOK, result{Msg: "New ID added"})
	} else {
		writeJSON(w, http.StatusOK, result{Msg: err.Error()})
	}
}

type result struct {
	Results []ch.Result `json:"results,omitempty"`
	Msg     string      `json:"msg,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, res result) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var (
		bytes []byte
		err   error
	)
	if bytes, err = json.Marshal(res); err != nil {
		bytes, _ = json.Marshal(result{Msg: fmt.Sprintf("Failed to create json: %s", err)})
	}
	w.WriteHeader(status)
	_, _ = w.Write(bytes)
	_, _ = w.Write([]byte("\n"))
}

func (s *Server) matchCoverHash(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	var (
		values    = r.URL.Query()
		ahashStr  = strings.TrimSpace(values.Get("ahash"))
		dhashStr  = strings.TrimSpace(values.Get("dhash"))
		phashStr  = strings.TrimSpace(values.Get("phash"))
		maxStr    = strings.TrimSpace(values.Get("max"))
		exactOnly = strings.ToLower(strings.TrimSpace(values.Get("exactOnly"))) != "false"
		simple    = strings.ToLower(strings.TrimSpace(values.Get("simple"))) == "true"
		ahash     uint64
		dhash     uint64
		phash     uint64
		max       int
		err       error
		hashes    []ch.Hash
	)

	if simple {
		writeJSON(w, http.StatusBadRequest, result{Msg: "Simple results are no longer Supported"})
		return
	}

	if ahash, err = strconv.ParseUint(ahashStr, 16, 64); err != nil && ahashStr != "" {
		log.Printf("could not parse ahash: %s", ahashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if ahash > 0 {
		hashes = append(hashes, ch.Hash{Hash: ahash, Kind: goimagehash.AHash})
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		log.Printf("could not parse dhash: %s", dhashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if dhash > 0 {
		hashes = append(hashes, ch.Hash{Hash: dhash, Kind: goimagehash.DHash})
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		log.Printf("could not parse phash: %s", phashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if phash > 0 {
		hashes = append(hashes, ch.Hash{Hash: phash, Kind: goimagehash.PHash})
	}
	if tmpMax, err := strconv.Atoi(maxStr); err != nil && maxStr != "" {
		log.Printf("Invalid Max: %s", maxStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Invalid Max: %s", maxStr)})
		return
	} else {
		max = tmpMax
	}

	if max > 8 {
		log.Printf("Max must be less than 9: %d", max)
		writeJSON(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Max must be less than 9: %d", max)})
		return
	}
	matches, err := s.hashes.GetMatches(hashes, max, exactOnly)
	slices.SortFunc(matches, func(a ch.Result, b ch.Result) int {
		return cmp.Compare(a.Distance, b.Distance)
	})
	log.Println(err)
	if len(matches) > 0 {
		var msg string
		if err != nil {
			msg = err.Error()
		}

		writeJSON(w, http.StatusOK, result{
			Results: matches,
			Msg:     msg,
		})
		return
	}

	writeJSON(w, http.StatusNotFound, result{Msg: "No hashes found"})
}

func (s *Server) addCover(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	if true {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	var (
		values = r.URL.Query()
		domain = strings.TrimSpace(values.Get("domain"))
		ID     = strings.TrimSpace(values.Get("id"))
	)

	if ID == "" {
		log.Println("No ID Provided")
		writeJSON(w, http.StatusBadRequest, result{Msg: "No ID Provided"})
		return
	}
	if domain == "" {
		log.Println("No domain Provided")
		writeJSON(w, http.StatusBadRequest, result{Msg: "No Domain Provided"})
		return
	}
	i, format, err := image.Decode(r.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		log.Println(msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	log.Printf("Decoded %s image from %s", format, user)
	select {
	case <-s.Context.Done():
		log.Println("Recieved quit")
		return
	default:
	}
	s.hashingQueue <- ch.Im{Im: i, Format: format, ID: ch.ID{Domain: ch.NewSource(domain), ID: ID}}
	writeJSON(w, http.StatusOK, result{Msg: "Success"})
}

func (s *Server) mapper(workerID int) {
	defer log.Println("Mapper", workerID, "completed")
	for hash := range s.mappingQueue {
		s.hashes.MapHashes(hash)
	}
}

func (s *Server) hasher(workerID int) {
	defer log.Println("Hasher", workerID, "completed")
	for image := range s.hashingQueue {
		start := time.Now()
		if image.NewOnly && len(s.hashes.GetIDs(image.ID)) > 0 {
			log.Printf("Skipping existing hash with ID: %s found", image.ID)
			continue
		}
		hash := ch.HashImage(image)
		if *hash.ID.Domain == "" || hash.ID.ID == "" {
			continue
		}

		select {
		// TODO: Check channel pipelines
		case s.mappingQueue <- hash:
		default:
		}

		elapsed := time.Since(start)
		log.Printf("Hashing took %v: worker: %v. %s: %064b id: %v\n", elapsed, workerID, hash.Hashes[0].Kind, hash.Hashes[0].Hash, hash.ID)
	}
}

func (s *Server) reader(workerID int) {
	defer log.Println("Reader", workerID, "completed")
	for path := range s.readerQueue {

		id := ch.ID{
			Domain: ch.NewSource(filepath.Base(filepath.Dir(filepath.Dir(path)))),
			ID:     filepath.Base(filepath.Dir(path)),
		}
		if s.onlyHashNewIDs && len(s.hashes.GetIDs(id)) > 0 {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			log.Printf("Failed to open image %q: %v", path, err)
			continue
		}
		i, format, err := image.Decode(bufio.NewReader(file))
		file.Close()
		if err != nil {
			continue // skip this image
		}

		im := ch.Im{
			Im:      i,
			Format:  format,
			ID:      id,
			NewOnly: s.onlyHashNewIDs,
		}
		select {
		case s.hashingQueue <- im:
		default:
		}
	}
}

func (s *Server) HashLocalImages(coverPath string) {
	if coverPath == "" {
		return
	}
	go func() {
		log.Println("Hashing covers at ", coverPath)
		start := time.Now()
		err := filepath.WalkDir(coverPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			select {
			case <-s.Context.Done():
				log.Println("Recieved quit")
				err = s.httpServer.Shutdown(context.TODO())
				return fmt.Errorf("recieved quit: %w", err)
			default:
			}
			if d.IsDir() {
				return nil
			}

			s.readerQueue <- path
			return nil
		})
		elapsed := time.Since(start)
		log.Println("Err:", err, "local hashing took", elapsed)
	}()
}
