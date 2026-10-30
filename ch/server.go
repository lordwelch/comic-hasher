package ch

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
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	gzip "github.com/klauspost/pgzip"

	"github.com/OneOfOne/xxhash"
	"github.com/twmb/murmur3"
	"github.com/zeebo/xxh3"

	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
)

var logger = log.NewLogger("server")

type Server struct {
	HTTPServer     *http.Server
	Mux            *CHMux
	BaseURL        *url.URL
	Storage        HashStorage
	HashServer     HashServer
	Context        context.Context
	cancel         func()
	ReaderQueue    chan string
	HashingQueue   chan Im
	MappingQueue   chan ImageHash
	OnlyHashNewIDs bool
	Version        string

	reg                 *prometheus.Registry
	matchCoverTotal     prometheus.Counter
	matchCoverDuration  *prometheus.HistogramVec
	hashCount           *prometheus.CounterVec
	lastRequestDuration prometheus.Gauge
}

func NewServer(ctx context.Context, Version string, addr string, onlyHashNewIDs bool) Server {
	mux := &CHMux{Version: Version, ServeMux: &http.ServeMux{}}
	ctx, cancel := context.WithCancel(ctx)

	s := Server{
		Context:      ctx,
		cancel:       cancel,
		ReaderQueue:  make(chan string, 1),
		HashingQueue: make(chan Im, 1),
		MappingQueue: make(chan ImageHash, 1),
		Mux:          mux,
		HTTPServer: &http.Server{
			Addr:           addr,
			Handler:        mux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
		OnlyHashNewIDs: onlyHashNewIDs,
		Version:        Version,
		reg:            prometheus.NewRegistry(),
	}

	s.setupAppHandlers()
	return s
}

type HashServer struct {
	hashes            string
	mut               sync.RWMutex
	digests           map[string][]byte
	digestHeaderCache string
	reprHeaderCache   string
	digesters         map[string]hash.Hash
	hashesDownloaded  prometheus.Counter
	gzip              *gzip.Writer
	useAllChecksums   bool
}

type CHMux struct {
	Version string
	*http.ServeMux
}

func (CHM *CHMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Comic-Hasher "+CHM.Version)
	CHM.ServeMux.ServeHTTP(w, r)
}

func (s *Server) Shutdown() error {
	s.cancel()
	// The server context has just been canceled so it cannot be used to bound a graceful shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.HTTPServer.Shutdown(ctx)
}

func (s *Server) ListenAndServe() error {
	err := s.HTTPServer.ListenAndServe()
	if err != nil {
		s.cancel()
		return err
	}

	return nil
}

func (s *Server) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	return strings.TrimSpace("lordwelch"), true
}

func (s *Server) setupAppHandlers() {
	s.Mux.HandleFunc("/add_cover", s.addCover)
	s.Mux.HandleFunc("/match_cover_hash", s.matchCoverHash)
	s.Mux.HandleFunc("/associate_ids", s.associateIDs)
	s.Mux.HandleFunc("/hashes", s.HashServer.DownloadHashes)
	s.Mux.Handle("/metrics", promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{}))
	promauto.With(s.reg)
	s.matchCoverTotal = promauto.With(s.reg).NewCounter(prometheus.CounterOpts{
		Name: "comic_hasher_match_cover_hash",
		Help: "The total number of processed /match_cover_hash requests",
	})

	s.HashServer.hashesDownloaded = promauto.With(s.reg).NewCounter(prometheus.CounterOpts{
		Name: "comic_hasher_hashes_download",
		Help: "The total number of times the hash database has been downloaded: /hashes",
	})

	s.hashCount = promauto.With(s.reg).NewCounterVec(prometheus.CounterOpts{
		Name: "comic_hasher_hashes",
		Help: "The total number of hashes",
	}, []string{"kind", "source"})
	s.matchCoverDuration = promauto.With(s.reg).NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "comic_hasher_match_cover_hash_request_seconds",
			Help: "Summary for the request duration of the /match_cover_hash",
		},
		[]string{"hashes"},
	)
	s.lastRequestDuration = promauto.With(s.reg).NewGauge(
		prometheus.GaugeOpts{
			Name: "comic_hasher_match_cover_hash_last_request_seconds",
			Help: "The request duration of the last /match_cover_hash request",
		},
	)
	promauto.With(s.reg).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "app_info",
			Help: "Current application version.",
		},
		[]string{"version"},
	).WithLabelValues(s.Version).Set(1)
}

func (h *HashServer) DownloadHashes(w http.ResponseWriter, r *http.Request) {
	h.mut.RLock()
	defer h.mut.RUnlock()
	if h.hashesDownloaded != nil {
		h.hashesDownloaded.Inc()
	}
	if r.Header.Get("Want-Digest") != "" {
		w.Header().Set("Digest", h.digestHeader())
	}
	w.Header().Set("Repr-Digest", h.reprDigestHeader())
	w.Header().Set("Content-Type", "application/x-image-hash-db+gzip")
	w.Header().Set("Content-Disposition", `"attachment; filename="hashes.gz"`)
	http.ServeFile(w, r, h.hashes)
}

func (h *HashServer) reprDigestHeader() string {
	if h.reprHeaderCache != "" {
		return h.reprHeaderCache
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
	str = str[:len(str)-1]
	h.reprHeaderCache = str
	return h.reprHeaderCache
}

func (h *HashServer) digestHeader() string {
	if h.digestHeaderCache != "" {
		return h.digestHeaderCache
	}
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
	str = str[:len(str)-1]
	h.digestHeaderCache = str
	return h.digestHeaderCache
}

func (h *HashServer) WriteHashes(hashes HashStorage) error {
	// Encoding hashes requires a lock as it assumes pointers are in use to reduce unnecessary memory usage
	logger.Println(log.Verbose, "Writing hashes to disk")
	defer logger.Println(log.Verbose, "Finished writing hashes to disk")
	hashes.RLock()
	defer hashes.RUnlock()
	encodedHashes, err := hashes.EncodeHashes()
	if err != nil {
		return err
	}
	tmpFilePath := h.hashes + ".tmp.gz"
	f, err := os.Create(tmpFilePath)
	if err != nil {
		return fmt.Errorf("failed to write hashes to temporary file %q, %w", h.hashes+".tmp", err)
	}

	defer f.Close() //nolint:errcheck
	writer := bufio.NewWriter(h.initDigests(f))
	h.gzip.Reset(writer)
	b := bufio.NewWriterSize(h.gzip, 32*1024)
	err = EncodeHashesV3(encodedHashes, b)
	if err != nil {
		return fmt.Errorf("failed to encode hashes to temporary file %q, %w", h.hashes+".tmp", err)
	}
	b.Flush()

	// Close gzip so we have a proper stream
	if err = h.gzip.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}
	writer.Flush()

	h.mut.Lock()
	defer h.mut.Unlock()
	h.digestHeaderCache = ""
	_ = f.Close()
	for name, digest := range h.digesters {
		h.digests[name] = digest.Sum(nil)
		digest.Reset() // may possibly keep some memory free...
	}
	err = os.Rename(tmpFilePath, h.hashes)
	if err != nil {
		return fmt.Errorf("failed to update existing file: %w", err)
	}
	return nil
}

func NewHashServer(hashes string, useAllChecksums bool) HashServer {
	if !filepath.IsAbs(hashes) {
		panic("NewHashServer needs an absolute path for hashes")
	}
	h := HashServer{
		hashes:          hashes,
		digests:         map[string][]byte{},
		useAllChecksums: useAllChecksums,
		gzip:            gzip.NewWriter(io.Discard),
	}
	f, err := os.Open(hashes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return h // nolint:govet
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

	return h // nolint:govet
}

func (h *HashServer) initDigests(writer io.Writer) io.Writer {
	if h.digesters == nil {
		h.digesters = map[string]hash.Hash{
			"sha":                  crypto.SHA1.New(),
			crypto.SHA1.String():   crypto.SHA1.New(),
			crypto.SHA256.String(): crypto.SHA256.New(),
			crypto.MD5.String():    crypto.MD5.New(),
			"XXH3":                 xxh3.New(),
		}
		if h.useAllChecksums {
			maps.Copy(h.digesters, map[string]hash.Hash{
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
			})
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
		domain    = Source(strings.ToLower(strings.TrimSpace(values.Get("domain"))))
		id        = strings.ToLower(strings.TrimSpace(values.Get("id")))
		newDomain = Source(strings.ToLower(strings.TrimSpace(values.Get("newDomain"))))
		newID     = strings.ToLower(strings.TrimSpace(values.Get("newID")))
	)
	if id == "" {
		msg := "No ID Provided"
		logger.Println(log.Verbose2, msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if domain == "" {
		msg := "No domain Provided"
		logger.Println(log.Verbose2, msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newID == "" {
		msg := "No newID Provided"
		logger.Println(log.Verbose2, msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newDomain == "" {
		msg := "No newDomain Provided"
		logger.Println(log.Verbose2, msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newDomain == domain {
		msg := "newDomain cannot be the same as the existing domain"
		logger.Println(log.Verbose2, msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	logger.Log(log.Standard, "Attempting to associate %s:%s to %s:%s", domain, id, newDomain, newID)
	err := s.Storage.AssociateIDs(
		ID{Domain: &domain, ID: id},
		ID{Domain: &newDomain, ID: newID},
	)

	if err == nil {
		writeJSON(w, http.StatusOK, result{Msg: "New ID added"})
	} else {
		writeJSON(w, http.StatusOK, result{Msg: err.Error()})
	}
}

type result struct {
	Results []Result `json:"results,omitempty"`
	Msg     string   `json:"msg,omitempty"`
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
		max       int = 8
		err       error
		hashes    []Hash
		hashStr   string
	)

	if simple {
		writeJSON(w, http.StatusBadRequest, result{Msg: "Simple results are no longer Supported"})
		return
	}

	if ahash, err = strconv.ParseUint(ahashStr, 16, 64); err != nil && ahashStr != "" {
		logger.Log(log.Verbose, "could not parse ahash: %s", ahashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if ahash > 0 {
		hashes = append(hashes, Hash{Hash: ahash, Kind: goimagehash.AHash})
		hashStr += "ahash_"
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		logger.Log(log.Verbose, "could not parse dhash: %s", dhashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if dhash > 0 {
		hashes = append(hashes, Hash{Hash: dhash, Kind: goimagehash.DHash})
		hashStr += "dhash_"
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		logger.Log(log.Verbose, "could not parse phash: %s", phashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if phash > 0 {
		hashes = append(hashes, Hash{Hash: phash, Kind: goimagehash.PHash})
		hashStr += "phash_"
	}
	if tmpMax, err := strconv.Atoi(maxStr); err != nil && maxStr != "" {
		logger.Log(log.Verbose, "Invalid Max: %s", maxStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Invalid Max: %s", maxStr)})
		return
	} else {
		if maxStr != "" {
			max = tmpMax
		}
	}

	hashStr = strings.TrimRight(hashStr, "_")

	if max > 8 {
		logger.Log(log.Verbose, "Max must be less than 9: %d", max)
		writeJSON(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Max must be less than 9: %d", max)})
		return
	}
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		s.matchCoverDuration.WithLabelValues(hashStr).Observe(v)
		s.lastRequestDuration.Set(v)
	}))
	defer timer.ObserveDuration()

	s.matchCoverTotal.Inc()
	matches, err := s.Storage.GetMatches(hashes, max, exactOnly)
	cmpFunc := func(a Result, b Result) int {
		return cmp.Or(
			cmp.Compare(a.Hash.Kind, b.Hash.Kind),
			cmp.Compare(a.Hash.Hash, b.Hash.Hash),
			a.ID.Compare(b.ID),
			cmp.Compare(a.Distance, b.Distance),
		)
	}
	slices.SortFunc(matches, cmpFunc)
	matches = slices.CompactFunc(matches, func(a, b Result) bool { return cmpFunc(a, b) == 0 })
	if err != nil {
		logger.Println(log.Required, "Internal error:", err)
		msg := err.Error()
		writeJSON(w, http.StatusInternalServerError, result{
			Results: matches,
			Msg:     msg,
		})
		return
	}
	if len(matches) == 0 {
		writeJSON(w, http.StatusNotFound, result{Msg: "No hashes found"})
		return
	}
	writeJSON(w, http.StatusOK, result{
		Results: matches,
	})
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
		id     = strings.TrimSpace(values.Get("id"))
	)

	if id == "" {
		logger.Println(log.Verbose, "No ID Provided")
		writeJSON(w, http.StatusBadRequest, result{Msg: "No ID Provided"})
		return
	}
	if domain == "" {
		logger.Println(log.Verbose, "No domain Provided")
		writeJSON(w, http.StatusBadRequest, result{Msg: "No Domain Provided"})
		return
	}
	i, format, err := image.Decode(r.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		logger.Println(log.Verbose, msg)
		writeJSON(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	logger.Log(log.Standard, "Decoded %s image from %s", format, user)
	select {
	case <-s.Context.Done():
		logger.Println(log.Verbose, "Recieved quit")
		return
	default:
	}
	s.HashingQueue <- Im{Im: i, Format: format, ID: ID{Domain: NewSource(domain), ID: id}}
	writeJSON(w, http.StatusOK, result{Msg: "Success"})
}

func (s *Server) Mapper(workerID int) {
	defer logger.Println(log.Verbose2, "Mapper", workerID, "completed")
	for hash := range s.MappingQueue {
		for m, count := range s.Storage.MapHashes(hash).Hashes {
			s.hashCount.WithLabelValues(m.Kind.String(), string(*m.Source)).Add(float64(count))
		}
	}
}

func (s *Server) Hasher(workerID int) {
	defer logger.Println(log.Verbose2, "Hasher", workerID, "completed")
	for image := range s.HashingQueue {
		start := time.Now()
		if image.NewOnly && len(s.Storage.GetIDs(image.ID)) > 0 {
			logger.Log(log.Verbose, "Skipping existing hash with ID: %s found", image.ID)
			continue
		}
		hash := HashImage(image)
		if *hash.ID.Domain == "" || hash.ID.ID == "" {
			continue
		}

		elapsed := time.Since(start)
		logger.Log(log.Verbose, "Hashing took %v: id: %v", elapsed, hash.ID)
		s.MappingQueue <- hash
	}
}

func (s *Server) DecodeHashes(loadedHashes *SavedHashesV3) {
	metrics, err := s.Storage.DecodeHashes(loadedHashes)
	if err != nil {
		panic(err)
	}
	for m, count := range metrics.Hashes {
		s.hashCount.WithLabelValues(m.Kind.String(), string(*m.Source)).Add(float64(count))
	}
}

func (s *Server) HashLocalImages(coverPath string) {
	if coverPath == "" {
		return
	}
	logger.Println(log.Standard, "Hashing covers at ", coverPath)
	start := time.Now()
	err := filepath.WalkDir(coverPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-s.Context.Done():
			return fmt.Errorf("recieved quit: %w", err)
		default:
		}
		if d.IsDir() {
			return nil
		}

		id := ID{
			Domain: NewSource(filepath.Base(filepath.Dir(filepath.Dir(path)))),
			ID:     filepath.Base(filepath.Dir(path)),
		}
		if s.OnlyHashNewIDs && len(s.Storage.GetIDs(id)) > 0 {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			logger.Log(log.Standard, "Failed to open image %q: %v", path, err)
			return nil
		}
		i, format, err := image.Decode(bufio.NewReader(file))
		file.Close()
		if err != nil {
			return nil // skip this image
		}

		im := Im{
			Im:      i,
			Format:  format,
			ID:      id,
			NewOnly: s.OnlyHashNewIDs,
		}
		select {
		case s.HashingQueue <- im:
		default:
		}
		return nil
	})
	elapsed := time.Since(start)
	logger.Println(log.Standard, "Err:", err, "local hashing took", elapsed)
}
