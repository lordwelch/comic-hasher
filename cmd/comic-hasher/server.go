package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
	"golang.org/x/exp/slices"
)

type Server struct {
	httpServer     *http.Server
	mux            *CHMux
	BaseURL        *url.URL
	hashes         ch.HashStorage
	Context        context.Context
	cancel         func()
	signalQueue    chan os.Signal
	readerQueue    chan string
	hashingQueue   chan ch.Im
	mappingQueue   chan ch.ImageHash
	onlyHashNewIDs bool
	version        string
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
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if domain == "" {
		msg := "No domain Provided"
		log.Println(msg)
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newID == "" {
		msg := "No newID Provided"
		log.Println(msg)
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newDomain == "" {
		msg := "No newDomain Provided"
		log.Println(msg)
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	if newDomain == domain {
		msg := "newDomain cannot be the same as the existing domain"
		log.Println(msg)
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	log.Printf("Attempting to associate %s:%s to %s:%s", domain, ID, newDomain, newID)
	err := s.hashes.AssociateIDs([]ch.NewIDs{{
		OldID: ch.ID{
			Domain: domain,
			ID:     ID,
		},
		NewID: ch.ID{
			Domain: newDomain,
			ID:     newID,
		},
	}})

	if err == nil {
		writeJson(w, http.StatusOK, result{Msg: "New ID added"})
	} else {
		writeJson(w, http.StatusOK, result{Msg: err.Error()})
	}
}

type result struct {
	Results []ch.Result `json:"results,omitempty"`
	Msg     string      `json:"msg,omitempty"`
}

func writeJson(w http.ResponseWriter, status int, res result) {
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
		max_tmp   int
		err       error
		hashes    []ch.Hash
	)

	if simple {
		writeJson(w, http.StatusBadRequest, result{Msg: "Simple results are no longer Supported"})
		return
	}

	if ahash, err = strconv.ParseUint(ahashStr, 16, 64); err != nil && ahashStr != "" {
		log.Printf("could not parse ahash: %s", ahashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if ahash > 0 {
		hashes = append(hashes, ch.Hash{Hash: ahash, Kind: goimagehash.AHash})
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		log.Printf("could not parse dhash: %s", dhashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if dhash > 0 {
		hashes = append(hashes, ch.Hash{Hash: dhash, Kind: goimagehash.DHash})
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		log.Printf("could not parse phash: %s", phashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if phash > 0 {
		hashes = append(hashes, ch.Hash{Hash: phash, Kind: goimagehash.PHash})
	}
	if max_tmp, err = strconv.Atoi(maxStr); err != nil && maxStr != "" {
		log.Printf("Invalid Max: %s", maxStr)
		writeJson(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Invalid Max: %s", maxStr)})
		return
	}
	if maxStr != "" {
		max = max_tmp
	}

	if max > 8 {
		log.Printf("Max must be less than 9: %d", max)
		writeJson(w, http.StatusBadRequest, result{Msg: fmt.Sprintf("Max must be less than 9: %d", max)})
		return
	}
	matches, err := s.hashes.GetMatches(hashes, max, exactOnly)
	slices.SortFunc(matches, func(a ch.Result, b ch.Result) int {
		return cmp.Compare(a.Distance, b.Distance)
	})
	log.Println(err)
	if len(matches) > 0 {
		var msg string = ""
		if err != nil {
			msg = err.Error()
		}

		writeJson(w, http.StatusOK, result{
			Results: matches,
			Msg:     msg,
		})
		return
	}

	writeJson(w, http.StatusNotFound, result{Msg: "No hashes found"})
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
		writeJson(w, http.StatusBadRequest, result{Msg: "No ID Provided"})
		return
	}
	if domain == "" {
		log.Println("No domain Provided")
		writeJson(w, http.StatusBadRequest, result{Msg: "No Domain Provided"})
		return
	}
	i, format, err := image.Decode(r.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		log.Println(msg)
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
		return
	}
	log.Printf("Decoded %s image from %s", format, user)
	select {
	case <-s.Context.Done():
		log.Println("Recieved quit")
		return
	default:
	}
	s.hashingQueue <- ch.Im{Im: i, Format: format, ID: ch.ID{Domain: ch.Source(domain), ID: ID}}
	writeJson(w, http.StatusOK, result{Msg: "Success"})
}

func (s *Server) mapper(done func()) {
	defer done()
	for hash := range s.mappingQueue {
		s.hashes.MapHashes(hash)
	}
}

func (s *Server) hasher(workerID int, done func(int)) {
	defer done(workerID)
	for image := range s.hashingQueue {
		start := time.Now()
		if image.NewOnly && len(s.hashes.GetIDs(image.ID)) > 0 {
			log.Printf("Skipping existing hash with ID: %s found", image.ID)
			continue
		}
		hash := ch.HashImage(image)
		if hash.ID.Domain == "" || hash.ID.ID == "" {
			continue
		}

		select {
		// TODO: Check channel pipelines
		case s.mappingQueue <- hash:
		default:
		}

		elapsed := time.Since(start)
		log.Printf("Hashing took %v: worker: %v. %s: %064b id: %s\n", elapsed, workerID, hash.Hashes[0].Kind, hash.Hashes[0].Hash, hash.ID)
	}
}

func (s *Server) reader(workerID int, done func(i int)) {
	defer done(workerID)
	for path := range s.readerQueue {
		id := ch.ID{Domain: ch.Source(filepath.Base(filepath.Dir(filepath.Dir(path)))), ID: filepath.Base(filepath.Dir(path))}
		if len(s.hashes.GetIDs(id)) > 0 {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			panic(err)
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

func (s *Server) HashLocalImages(opts Opts) {
	if opts.coverPath == "" {
		return
	}
	go func() {
		log.Println("Hashing covers at ", opts.coverPath)
		start := time.Now()
		err := filepath.WalkDir(opts.coverPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			select {
			case <-s.Context.Done():
				log.Println("Recieved quit")
				err = s.httpServer.Shutdown(context.TODO())
				return fmt.Errorf("Recieved quit: %w", err)
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
