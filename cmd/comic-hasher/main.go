package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/disintegration/imaging"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
	// "github.com/google/uuid"
	// "github.com/zitadel/oidc/pkg/client/rp"
	// httphelper "github.com/zitadel/oidc/pkg/http"
	// "github.com/zitadel/oidc/pkg/oidc"
)

type Server struct {
	httpServer *http.Server
	mux        *http.ServeMux
	BaseURL    *url.URL
	// token         chan<- *oidc.Tokens
	// Partial hashes are a uint64 split into 8 pieces or a unint64 for quick lookup, the value is an index to covers
	PartialAhash [8]map[uint8][]uint64
	PartialDhash [8]map[uint8][]uint64
	PartialPhash [8]map[uint8][]uint64
	FullAhash    map[uint64][]string // Maps ahash's to lists of ID's   domain:id
	FullDhash    map[uint64][]string // Maps dhash's to lists of ID's   domain:id
	FullPhash    map[uint64][]string // Maps phash's to lists of ID's   domain:id
	ids          map[ch.Source]map[string]struct{}
	hashMutex    sync.RWMutex
	quit         chan struct{}
	signalQueue  chan os.Signal
	readerQueue  chan string
	hashingQueue chan ch.Im
	mappingQueue chan ch.Hash
}

// var key = []byte(uuid.New().String())[:16]

type savedHashes map[ch.Source]map[string][3]uint64

type Format int

const (
	Msgpack = iota + 1
	JSON
)

var formatNames = map[Format]string{
	JSON:    "json",
	Msgpack: "msgpack",
}

var formatValues = map[string]Format{
	"json":    JSON,
	"msgpack": Msgpack,
}

func (f Format) String() string {
	if name, known := formatNames[f]; known {
		return name
	}
	return "Unknown"
}

type Encoder func(any) ([]byte, error)
type Decoder func([]byte, interface{}) error

func (f *Format) Set(s string) error {
	if format, known := formatValues[strings.ToLower(s)]; known {
		*f = format
	} else {
		return fmt.Errorf("Unknown format: %d", f)
	}
	return nil
}

type Opts struct {
	cpuprofile         string
	coverPath          string
	loadEmbeddedHashes bool
	saveEmbeddedHashes bool
	format             Format
	hashesPath         string
}

func main() {
	opts := Opts{format: Msgpack} // flag is weird
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	flag.StringVar(&opts.cpuprofile, "cpuprofile", "", "Write cpu profile to file")

	flag.StringVar(&opts.coverPath, "cover-path", "", "Path to covers to add to hash database. must be in the form '{cover-path}/{domain}/{id}/*' eg for --cover-path /covers it should look like /covers/comicvine.gamespot.com/10000/image.gif")
	flag.BoolVar(&opts.loadEmbeddedHashes, "use-embedded-hashes", true, "Use hashes embedded in the application as a starting point")
	flag.BoolVar(&opts.saveEmbeddedHashes, "save-embedded-hashes", false, "Save hashes even if we loaded the embedded hashes")
	flag.StringVar(&opts.hashesPath, "hashes", "hashes.gz", "Path to optionally gziped hashes in msgpack or json format. You must disable embedded hashes to use this option")
	flag.Var(&opts.format, "save-format", "Specify the format to export hashes to (json, msgpack)")
	flag.Parse()

	if opts.coverPath != "" {
		_, err := os.Stat(opts.coverPath)
		if err != nil {
			panic(err)
		}
	}
	startServer(opts)
}

func (s *Server) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	return strings.TrimSpace("lordwelch"), true
}

func (s *Server) setupAppHandlers() {
	// s.mux.HandleFunc("/get_cover", s.getCover)
	s.mux.HandleFunc("/add_cover", s.addCover)
	s.mux.HandleFunc("/match_cover_hash", s.matchCoverHash)
	s.mux.HandleFunc("/associate_ids", s.associateIDs)
}

func (s *Server) getCover(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	var (
		values = r.URL.Query()
		domain = strings.TrimSpace(values.Get("domain"))
		ID     = strings.TrimSpace(values.Get("id"))
	)
	if ID == "" {
		log.Println("No ID Provided")
		http.Error(w, "No ID Provided", http.StatusBadRequest)
		return
	}
	if domain == "" {
		log.Println("No domain Provided")
		http.Error(w, "No domain Provided", http.StatusBadRequest)
		return
	}
	// if index, ok := s.IDToCover[domain+":"+ID]; ok {
	// 	covers, err := json.Marshal(s.covers[index])
	// 	if err == nil {
	// 		w.Header().Add("Content-Type", "application/json")
	// 		w.Write(covers)
	// 		return
	// 	}
	// }
	fmt.Fprintln(w, "Not implemented")
}

func (s *Server) associateIDs(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	var (
		values    = r.URL.Query()
		domain    = strings.TrimSpace(values.Get("domain"))
		ID        = strings.TrimSpace(values.Get("id"))
		newDomain = strings.TrimSpace(values.Get("newDomain"))
		newID     = strings.TrimSpace(values.Get("newID"))
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
	if _, domainExists := s.ids[ch.Source(domain)]; !domainExists {
		msg := "No IDs belonging to " + domain + "exist on this server"
		log.Println(msg)
		writeJson(w, http.StatusBadRequest, result{Msg: msg})
	}
	log.Printf("Attempting to associate %s:%s to %s:%s", domain, ID, newDomain, newID)
	found := false
	for _, hash := range []map[uint64][]string{s.FullAhash, s.FullDhash, s.FullPhash} {
		for i, idlist := range hash {
			if _, found_in_hash := slices.BinarySearch(idlist, domain+":"+ID); found_in_hash {
				found = true
				hash[i] = ch.Insert(idlist, newDomain+":"+newID)
				if _, ok := s.ids[ch.Source(newDomain)]; !ok {
					s.ids[ch.Source(newDomain)] = make(map[string]struct{})
				}
				s.ids[ch.Source(newDomain)][newID] = struct{}{}
			}
		}
	}
	if found {
		writeJson(w, http.StatusOK, result{Msg: "New ID added"})
	} else {
		writeJson(w, http.StatusOK, result{Msg: "Old ID not found"})
	}
}

func (s *Server) getMatches(ahash, dhash, phash uint64, max int, skipNonExact bool) []ch.Result {
	var foundMatches []ch.Result
	s.hashMutex.RLock()
	defer s.hashMutex.RUnlock()

	if skipNonExact { // exact matches are also found by partial matches. Don't bother with exact matches so we don't have to de-duplicate
		if matchedResults, ok := s.FullAhash[ahash]; ok && ahash != 0 {
			foundMatches = append(foundMatches, ch.Result{IDs: matchedResults, Distance: 0, Hash: ch.ImageHash{Hash: ahash, Kind: goimagehash.AHash}})
		}
		if matchedResults, ok := s.FullDhash[dhash]; ok && dhash != 0 {
			foundMatches = append(foundMatches, ch.Result{IDs: matchedResults, Distance: 0, Hash: ch.ImageHash{Hash: dhash, Kind: goimagehash.DHash}})
		}
		if matchedResults, ok := s.FullPhash[phash]; ok && phash != 0 {
			foundMatches = append(foundMatches, ch.Result{IDs: matchedResults, Distance: 0, Hash: ch.ImageHash{Hash: phash, Kind: goimagehash.PHash}})
		}

		// If we have exact matches don't bother with other matches
		if len(foundMatches) > 0 && skipNonExact {
			return foundMatches
		}
	}

	foundHashes := make(map[uint64]struct{})
	if ahash != 0 {
		for i, partialHash := range ch.SplitHash(ahash) {
			for _, match := range ch.Atleast(max, ahash, s.PartialAhash[i][partialHash]) {
				_, alreadyMatched := foundHashes[match.Hash]
				if matchedResults, ok := s.FullAhash[match.Hash]; ok && !alreadyMatched {
					foundHashes[match.Hash] = struct{}{}
					foundMatches = append(foundMatches, ch.Result{IDs: matchedResults, Distance: match.Distance, Hash: ch.ImageHash{Hash: match.Hash, Kind: goimagehash.AHash}})
				}
			}
		}
	}

	foundHashes = make(map[uint64]struct{})
	if dhash != 0 {
		for i, partialHash := range ch.SplitHash(dhash) {
			for _, match := range ch.Atleast(max, dhash, s.PartialDhash[i][partialHash]) {
				_, alreadyMatched := foundHashes[match.Hash]
				if matchedResults, ok := s.FullDhash[match.Hash]; ok && !alreadyMatched {
					foundHashes[match.Hash] = struct{}{}
					foundMatches = append(foundMatches, ch.Result{IDs: matchedResults, Distance: match.Distance, Hash: ch.ImageHash{Hash: match.Hash, Kind: goimagehash.DHash}})
				}
			}
		}
	}

	foundHashes = make(map[uint64]struct{})
	if phash != 0 {
		for i, partialHash := range ch.SplitHash(phash) {
			for _, match := range ch.Atleast(max, phash, s.PartialPhash[i][partialHash]) {
				_, alreadyMatched := foundHashes[match.Hash]
				if matchedResults, ok := s.FullPhash[match.Hash]; ok && !alreadyMatched {
					foundHashes[match.Hash] = struct{}{}
					foundMatches = append(foundMatches, ch.Result{IDs: matchedResults, Distance: match.Distance, Hash: ch.ImageHash{Hash: match.Hash, Kind: goimagehash.PHash}})
				}
			}
		}
	}

	return foundMatches
}

type SimpleResult struct {
	Distance int
	IDList   ch.IDList
}

func getSimpleResults(fullResults []ch.Result) []SimpleResult {
	simpleResult := make([]SimpleResult, 0, len(fullResults))

	slices.SortFunc(fullResults, func(a, b ch.Result) int {
		return cmp.Compare(a.Distance, b.Distance)
	})

	// Deduplicate IDs
	idToDistance := make(map[string]int)
	for _, fullResult := range fullResults {
		for _, id := range fullResult.IDs {
			if distance, ok := idToDistance[id]; !ok || fullResult.Distance < distance {
				idToDistance[id] = fullResult.Distance
			}
		}
	}

	// Group by distance
	distanceMap := make(map[int]SimpleResult)
	for id, distance := range idToDistance {
		var (
			sr SimpleResult
			ok bool
		)
		if sr, ok = distanceMap[distance]; !ok {
			sr.IDList = make(ch.IDList)
		}
		sourceID := strings.SplitN(id, ":", 2)
		sr.Distance = distance
		sr.IDList[ch.Source(sourceID[0])] = append(sr.IDList[ch.Source(sourceID[0])], sourceID[1])
		distanceMap[distance] = sr
	}

	// turn into array
	for _, sr := range distanceMap {
		simpleResult = append(simpleResult, sr)
	}
	return simpleResult
}

type APIResult struct {
	IDList   ch.IDList
	Distance int
	Hash     ch.ImageHash
}

func getResults(fullResults []ch.Result) []APIResult {
	apiResults := make([]APIResult, 0, len(fullResults))
	for _, res := range fullResults {
		idlist := make(ch.IDList)
		for _, id := range res.IDs {
			sourceID := strings.SplitN(id, ":", 2)
			idlist[ch.Source(sourceID[0])] = append(idlist[ch.Source(sourceID[0])], sourceID[1])
		}
		apiResults = append(apiResults,
			APIResult{
				Distance: res.Distance,
				Hash:     res.Hash,
				IDList:   idlist,
			},
		)
	}
	return apiResults
}

type result struct {
	Results any    `json:"results,omitempty"`
	Msg     string `json:"msg,omitempty"`
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
		values       = r.URL.Query()
		ahashStr     = strings.TrimSpace(values.Get("ahash"))
		dhashStr     = strings.TrimSpace(values.Get("dhash"))
		phashStr     = strings.TrimSpace(values.Get("phash"))
		maxStr       = strings.TrimSpace(values.Get("max"))
		skipNonExact = strings.ToLower(strings.TrimSpace(values.Get("skipNonExact"))) != "false"
		simple       = strings.ToLower(strings.TrimSpace(values.Get("simple"))) == "true"
		ahash        uint64
		dhash        uint64
		phash        uint64
		max          int = 8
		max_tmp      int
		err          error
	)

	if ahash, err = strconv.ParseUint(ahashStr, 16, 64); err != nil && ahashStr != "" {
		log.Printf("could not parse ahash: %s", ahashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		log.Printf("could not parse dhash: %s", dhashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		log.Printf("could not parse phash: %s", phashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
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
	matches := s.getMatches(ahash, dhash, phash, max, skipNonExact)
	if len(matches) > 0 {
		if simple {
			writeJson(w, http.StatusOK, result{Results: getSimpleResults(matches)})
			return
		}
		writeJson(w, http.StatusOK, result{Results: getResults(matches)})
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
	case <-s.quit:
		log.Println("Recieved quit")
		return
	default:
	}
	s.hashingQueue <- ch.Im{Im: i, Format: format, Domain: ch.Source(domain), ID: ID, Path: ""}
	writeJson(w, http.StatusOK, result{Msg: "Success"})
}

func (s *Server) MapHashes(hash ch.Hash) {
	s.hashMutex.Lock()
	defer s.hashMutex.Unlock()
	s.mapHashes(hash.Ahash.GetHash(), hash.Dhash.GetHash(), hash.Phash.GetHash(), hash.Domain, hash.ID)
}

func (s *Server) mapHashes(ahash, dhash, phash uint64, domain ch.Source, id string) {

	if _, ok := s.ids[domain]; !ok {
		s.ids[domain] = make(map[string]struct{})
	}
	s.ids[domain][id] = struct{}{}

	if _, ok := s.FullAhash[ahash]; !ok {
		s.FullAhash[ahash] = make([]string, 0, 3)
	}
	s.FullAhash[ahash] = ch.Insert(s.FullAhash[ahash], string(domain)+":"+id)

	if _, ok := s.FullDhash[dhash]; !ok {
		s.FullDhash[dhash] = make([]string, 0, 3)
	}
	s.FullDhash[dhash] = ch.Insert(s.FullDhash[dhash], string(domain)+":"+id)

	if _, ok := s.FullPhash[phash]; !ok {
		s.FullPhash[phash] = make([]string, 0, 3)
	}
	s.FullPhash[phash] = ch.Insert(s.FullPhash[phash], string(domain)+":"+id)

	for i, partialHash := range ch.SplitHash(ahash) {
		s.PartialAhash[i][partialHash] = append(s.PartialAhash[i][partialHash], ahash)
	}
	for i, partialHash := range ch.SplitHash(dhash) {
		s.PartialDhash[i][partialHash] = append(s.PartialDhash[i][partialHash], dhash)
	}
	for i, partialHash := range ch.SplitHash(phash) {
		s.PartialPhash[i][partialHash] = append(s.PartialPhash[i][partialHash], phash)
	}
}

func (s *Server) initHashes() {
	for i := range s.PartialAhash {
		s.PartialAhash[i] = make(map[uint8][]uint64)
	}
	for i := range s.PartialDhash {
		s.PartialDhash[i] = make(map[uint8][]uint64)
	}
	for i := range s.PartialPhash {
		s.PartialPhash[i] = make(map[uint8][]uint64)
	}
	s.FullAhash = make(map[uint64][]string)
	s.FullDhash = make(map[uint64][]string)
	s.FullPhash = make(map[uint64][]string)
	s.ids = make(map[ch.Source]map[string]struct{})
}

func (s *Server) mapper(done func()) {
	defer done()
	for hash := range s.mappingQueue {
		s.MapHashes(hash)
	}
}

func (s *Server) hasher(workerID int, done func()) {
	defer done()
	for image := range s.hashingQueue {
		start := time.Now()

		hash := ch.HashImage(image)
		if hash.Domain == "" {
			continue
		}

		select {
		case <-s.quit:
			log.Println("Recieved quit")
			return
		case s.mappingQueue <- hash:
		default:
		}

		elapsed := time.Since(start)
		log.Printf("Hashing took %v: worker: %v. path: %s ahash: %064b id: %s\n", elapsed, workerID, image.Path, hash.Ahash.GetHash(), hash.ID)
	}
}

func (s *Server) reader(workerID int, done func()) {
	defer done()
	for path := range s.readerQueue {
		file, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		i, format, err := image.Decode(bufio.NewReader(file))
		if err != nil {
			continue // skip this image
		}
		file.Close()

		im := ch.Im{Im: i, Format: format, Domain: ch.Source(filepath.Base(filepath.Dir(filepath.Dir(path)))), ID: filepath.Base(filepath.Dir(path)), Path: path}
		select {
		case <-s.quit:
			log.Println("Recieved quit")
			return
		case s.hashingQueue <- im:
		default:
		}
	}
}

func (s *Server) encodeHashes(e Encoder) ([]byte, error) {
	hashes := make(savedHashes)
	for source, ids := range s.ids {
		hashes[source] = make(map[string][3]uint64, len(ids))
	}
	for hash, idlist := range s.FullAhash {
		for _, id := range idlist {
			sourceID := strings.SplitN(id, ":", 2)
			h := hashes[ch.Source(sourceID[0])][sourceID[1]]
			h[0] = hash
			hashes[ch.Source(sourceID[0])][sourceID[1]] = h
		}
	}
	for hash, idlist := range s.FullDhash {
		for _, id := range idlist {
			sourceID := strings.SplitN(id, ":", 2)
			h := hashes[ch.Source(sourceID[0])][sourceID[1]]
			h[1] = hash
			hashes[ch.Source(sourceID[0])][sourceID[1]] = h
		}

	}
	for hash, idlist := range s.FullPhash {
		for _, id := range idlist {
			sourceID := strings.SplitN(id, ":", 2)
			h := hashes[ch.Source(sourceID[0])][sourceID[1]]
			h[2] = hash
			hashes[ch.Source(sourceID[0])][sourceID[1]] = h
		}

	}
	return e(hashes)
}

// EncodeHashes must have a lock to s.hashMutex
func (s *Server) EncodeHashes(format Format) ([]byte, error) {
	switch format {
	case Msgpack:
		return s.encodeHashes(msgpack.Marshal)
	case JSON:
		return s.encodeHashes(json.Marshal)

	default:
		return nil, fmt.Errorf("Unknown format: %v", format)
	}
}

func (s *Server) decodeHashes(d Decoder, hashes []byte) error {
	loadedHashes := make(savedHashes)
	err := d(hashes, &loadedHashes)
	if err != nil {
		return err
	}

	for domain, ids := range loadedHashes {
		for id := range ids {
			if _, ok := s.ids[domain]; ok {
				s.ids[domain][id] = struct{}{}
			} else {
				s.ids[domain] = make(map[string]struct{})
			}
		}
	}
	for _, sourceHashes := range loadedHashes {
		s.FullAhash = make(map[uint64][]string, len(sourceHashes))
		s.FullDhash = make(map[uint64][]string, len(sourceHashes))
		s.FullPhash = make(map[uint64][]string, len(sourceHashes))
		break
	}
	for domain, sourceHashes := range loadedHashes {
		for id, h := range sourceHashes {
			s.mapHashes(h[0], h[1], h[2], domain, id)
		}
	}
	return nil
}

// DecodeHashes must have a lock to s.hashMutex
func (s *Server) DecodeHashes(format Format, hashes []byte) error {
	switch format {
	case Msgpack:
		return s.decodeHashes(msgpack.Unmarshal, hashes)
	case JSON:
		return s.decodeHashes(json.Unmarshal, hashes)

	default:
		return fmt.Errorf("Unknown format: %v", format)
	}
}

func (s *Server) HashLocalImages(opts Opts) {
	go func() {
		alreadyQuit := false
		if opts.coverPath == "" {
			select {
			case sig := <-s.signalQueue:
				log.Printf("Signal: %v\n", sig)
				close(s.quit)
			case <-s.quit:
				log.Println("Recieved quit")
			}
			err := s.httpServer.Shutdown(context.TODO())
			fmt.Println("Err:", err)
			return
		}
		fmt.Println("Hashing covers at ", opts.coverPath)
		start := time.Now()
		err := filepath.WalkDir(opts.coverPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			select {
			case signal := <-s.signalQueue:
				err = s.httpServer.Shutdown(context.TODO())
				alreadyQuit = true
				close(s.quit)
				return fmt.Errorf("signal: %v, %w", signal, err)
			case <-s.quit:
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
		fmt.Println("Err:", err, "local hashing took", elapsed)

		sig := <-s.signalQueue
		if !alreadyQuit {
			close(s.quit)
		}
		err = s.httpServer.Shutdown(context.TODO())
		log.Printf("Signal: %v, error: %v", sig, err)
	}()
}

func startServer(opts Opts) {
	if opts.cpuprofile != "" {
		f, err := os.Create(opts.cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	mux := http.NewServeMux()
	server := Server{
		// token:        make(chan *oidc.Tokens),
		quit:         make(chan struct{}),
		signalQueue:  make(chan os.Signal, 1),
		readerQueue:  make(chan string, 1120130), // Number gotten from checking queue size
		hashingQueue: make(chan ch.Im),
		mappingQueue: make(chan ch.Hash),
		mux:          mux,
		httpServer: &http.Server{
			Addr:           ":8080",
			Handler:        mux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
	}
	Notify(server.signalQueue)
	imaging.SetMaxProcs(1)
	fmt.Println("init hashes")
	server.initHashes()
	// server.setupOauthHandlers()
	fmt.Println("init handlers")
	server.setupAppHandlers()
	fmt.Println("init hashers")
	rwg := sync.WaitGroup{}
	for i := range 10 {
		rwg.Add(1)
		go server.reader(i, func() { fmt.Println("Reader completed"); rwg.Done() })
	}

	hwg := sync.WaitGroup{}
	for i := range 10 {
		hwg.Add(1)
		go server.hasher(i, func() { fmt.Println("Hasher completed"); hwg.Done() })
	}

	fmt.Println("init mapper")
	mwg := sync.WaitGroup{}
	mwg.Add(1)
	go server.mapper(func() { fmt.Println("Mapper completed"); mwg.Done() })

	if opts.loadEmbeddedHashes && len(ch.Hashes) != 0 {
		var err error
		hashes := ch.Hashes
		if gr, err := gzip.NewReader(bytes.NewReader(ch.Hashes)); err == nil {
			hashes, err = io.ReadAll(gr)
			if err != nil {
				panic(fmt.Sprintf("Failed to read embedded hashes: %s", err))
			}
		}

		var format Format
		for _, format = range []Format{Msgpack, JSON} {
			if err = server.DecodeHashes(format, hashes); err == nil {
				break
			}
		}
		if err != nil {
			panic(fmt.Sprintf("Failed to decode embedded hashes: %s", err))
		}
		fmt.Printf("Loaded embedded %s hashes ahashes: %d dhashes: %d phashes: %d\n", format, len(server.FullAhash), len(server.FullDhash), len(server.FullPhash))
	} else {
		if f, err := os.Open(opts.hashesPath); err == nil {
			var buf io.Reader = f
			if gr, err := gzip.NewReader(buf); err == nil {
				buf = bufio.NewReader(gr)
			} else {
				_, _ = f.Seek(0, io.SeekStart)
			}
			hashes, err := io.ReadAll(buf)
			f.Close()
			if err != nil {
				panic(fmt.Sprintf("Failed to load hashes from disk: %s", err))
			}

			var format Format
			for _, format = range []Format{Msgpack, JSON} {
				if err = server.DecodeHashes(format, hashes); err == nil {
					break
				}
			}

			if err != nil {
				panic(fmt.Sprintf("Failed to decode hashes from disk: %s", err))
			}
			fmt.Printf("Loaded hashes from %q %s hashes ahashes: %d dhashes: %d phashes: %d\n", opts.hashesPath, format, len(server.FullAhash), len(server.FullDhash), len(server.FullPhash))
		} else {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Println("No saved hashes to load")
			} else {
				fmt.Println("Unable to load saved hashes", err)
			}
		}
	}

	server.HashLocalImages(opts)

	fmt.Println("Listening on ", server.httpServer.Addr)
	err := server.httpServer.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
	close(server.readerQueue)
	fmt.Println("waiting on readers")
	rwg.Wait()
	for range server.readerQueue {
	}
	close(server.hashingQueue)
	fmt.Println("waiting on hashers")
	hwg.Wait()
	for range server.hashingQueue {
	}
	close(server.mappingQueue)
	fmt.Println("waiting on mapper")
	mwg.Wait()
	for range server.mappingQueue {
	}
	close(server.signalQueue)
	for range server.signalQueue {
	}

	if !opts.loadEmbeddedHashes || opts.saveEmbeddedHashes {
		encodedHashes, err := server.EncodeHashes(opts.format)
		if err == nil {
			if f, err := os.Create(opts.hashesPath); err == nil {
				gzw := gzip.NewWriter(f)
				_, err := gzw.Write(encodedHashes)
				if err != nil {
					fmt.Println("Failed to write hashes", err)
				} else {
					fmt.Println("Successfully saved hashes")
				}
				gzw.Close()
				f.Close()
			} else {
				fmt.Println("Unabled to save hashes", err)
			}
		} else {
			fmt.Printf("Unable to encode hashes as %v: %v", opts.format, err)
		}
	}
}
