package main

import (
	"bufio"
	"cmp"
	"compress/gzip"
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
	httpServer     *http.Server
	mux            *CHMux
	BaseURL        *url.URL
	storage        ch.HashStorage
	hashServer     HashServer
	Context        context.Context
	cancel         func()
	signalQueue    chan os.Signal
	readerQueue    chan string
	hashingQueue   chan ch.Im
	mappingQueue   chan ch.ImageHash
	onlyHashNewIDs bool
	version        string

	reg                   *prometheus.Registry
	match_cover_total     prometheus.Counter
	match_cover_duration  *prometheus.HistogramVec
	hash_count            *prometheus.CounterVec
	last_request_duration prometheus.Gauge
}

type HashServer struct {
	hashes            string
	mut               sync.RWMutex
	digests           map[string][]byte
	digestHeaderCache string
	format            ch.Format
	digesters         map[string]hash.Hash
	hashes_downloaded prometheus.Counter
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
	s.mux.Handle("/metrics", promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{}))
	promauto.With(s.reg)
	s.match_cover_total = promauto.With(s.reg).NewCounter(prometheus.CounterOpts{
		Name: "comic_hasher_match_cover_hash",
		Help: "The total number of processed /match_cover_hash requests",
	})

	s.hashServer.hashes_downloaded = promauto.With(s.reg).NewCounter(prometheus.CounterOpts{
		Name: "comic_hasher_hashes_download",
		Help: "The total number of times the hash database has been downloaded: /hashes",
	})

	s.hash_count = promauto.With(s.reg).NewCounterVec(prometheus.CounterOpts{
		Name: "comic_hasher_hashes",
		Help: "The total number of hashes",
	}, []string{"kind", "source"})
	s.match_cover_duration = promauto.With(s.reg).NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "comic_hasher_match_cover_hash_request_seconds",
			Help: "Summary for the request duration of the /match_cover_hash",
		},
		[]string{"hashes"},
	)
	s.last_request_duration = promauto.With(s.reg).NewGauge(
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
	).WithLabelValues(Version).Set(1)
}

func (h *HashServer) downloadHashes(w http.ResponseWriter, r *http.Request) {
	h.mut.RLock()
	defer h.mut.RUnlock()
	h.hashes_downloaded.Inc()
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
	tmp_file_path := h.hashes + ".tmp.gz"
	f, err := os.Create(tmp_file_path)
	if err != nil {
		return fmt.Errorf("failed to write hashes to temporary file %q, %w", h.hashes+".tmp", err)
	}

	defer f.Close() //nolint:errcheck
	writer := h.initDigests(f)
	gzw := gzip.NewWriter(writer)
	_, err = gzw.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write hashes to temporary file %q, %w", h.hashes+".tmp", err)
	}

	// Close gzip so we have a proper stream
	if err = gzw.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
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
	err = os.Rename(tmp_file_path, h.hashes)
	if err != nil {
		return fmt.Errorf("failed to update existing file%w", err)
	}
	return nil
}

func NewHashServer(hashes string, format ch.Format) HashServer {
	if !filepath.IsAbs(hashes) {
		panic("NewHashServer needs an absolute path for hashes")
	}
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
	logger.Log(log.Standard, "Attempting to associate %s:%s to %s:%s", domain, ID, newDomain, newID)
	err := s.storage.AssociateIDs([]ch.NewIDs{{
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
		max       int = 8
		err       error
		hashes    []ch.Hash
		hash_str  string
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
		hashes = append(hashes, ch.Hash{Hash: ahash, Kind: goimagehash.AHash})
		hash_str += "ahash_"
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		logger.Log(log.Verbose, "could not parse dhash: %s", dhashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if dhash > 0 {
		hashes = append(hashes, ch.Hash{Hash: dhash, Kind: goimagehash.DHash})
		hash_str += "dhash_"
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		logger.Log(log.Verbose, "could not parse phash: %s", phashStr)
		writeJSON(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if phash > 0 {
		hashes = append(hashes, ch.Hash{Hash: phash, Kind: goimagehash.PHash})
		hash_str += "phash_"
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

	hash_str = strings.TrimRight(hash_str, "_")

	if max > 8 {
		logger.Log(log.Verbose, "Max must be less than 9: %d", max)
		writeJSON(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Max must be less than 9: %d", max)})
		return
	}
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		s.match_cover_duration.WithLabelValues(hash_str).Observe(v)
		s.last_request_duration.Set(v)
	}))
	defer timer.ObserveDuration()

	s.match_cover_total.Inc()
	matches, err := s.storage.GetMatches(hashes, max, exactOnly)
	cmpFunc := func(a ch.Result, b ch.Result) int {
		return cmp.Or(
			cmp.Compare(a.Hash.Kind, b.Hash.Kind),
			cmp.Compare(a.Hash.Hash, b.Hash.Hash),
			a.ID.Compare(b.ID),
			cmp.Compare(a.Distance, b.Distance),
		)
	}
	slices.SortFunc(matches, cmpFunc)
	matches = slices.CompactFunc(matches, func(a ch.Result, b ch.Result) bool { return cmpFunc(a, b) == 0 })
	if len(matches) > 0 {
		var (
			msg    string
			status = http.StatusOK
		)
		// TODO: Output this even if we don't have matches
		if err != nil {
			logger.Println(log.Required, "Internal error:", err)
			status = http.StatusInternalServerError
			msg = err.Error()
		}

		writeJSON(w, status, result{
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
	s.hashingQueue <- ch.Im{Im: i, Format: format, ID: ch.ID{Domain: ch.NewSource(domain), ID: ID}}
	writeJSON(w, http.StatusOK, result{Msg: "Success"})
}

func (s *Server) mapper(workerID int) {
	defer logger.Println(log.Verbose2, "Mapper", workerID, "completed")
	for hash := range s.mappingQueue {
		for m, count := range s.storage.MapHashes(hash).Hashes {
			s.hash_count.WithLabelValues(m.Kind.String(), string(*m.Source)).Add(float64(count))
		}
	}
}

func (s *Server) hasher(workerID int) {
	defer logger.Println(log.Verbose2, "Hasher", workerID, "completed")
	for image := range s.hashingQueue {
		start := time.Now()
		if image.NewOnly && len(s.storage.GetIDs(image.ID)) > 0 {
			logger.Log(log.Verbose, "Skipping existing hash with ID: %s found", image.ID)
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
		logger.Log(log.Verbose, "Hashing took %v: id: %v", elapsed, hash.ID)
		if hash.ID.ID == "136787" {
			for _, h := range hash.Hashes {
				logger.Log(log.Standard, "Mapped Hash: %#v", h)
			}
		}
	}
}

func (s *Server) reader(workerID int) {
	defer logger.Println(log.Verbose2, "Reader", workerID, "completed")
	for path := range s.readerQueue {

		id := ch.ID{
			Domain: ch.NewSource(filepath.Base(filepath.Dir(filepath.Dir(path)))),
			ID:     filepath.Base(filepath.Dir(path)),
		}
		if s.onlyHashNewIDs && len(s.storage.GetIDs(id)) > 0 {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			logger.Log(log.Standard, "Failed to open image %q: %v", path, err)
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
		logger.Println(log.Standard, "Hashing covers at ", coverPath)
		start := time.Now()
		err := filepath.WalkDir(coverPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			select {
			case <-s.Context.Done():
				logger.Println(log.Verbose, "Recieved quit")
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
		logger.Println(log.Standard, "Err:", err, "local hashing took", elapsed)
	}()
}
