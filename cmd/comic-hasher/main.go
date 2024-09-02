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

	"github.com/kr/pretty"

	"github.com/vmihailenco/msgpack/v5"

	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
)

type Server struct {
	httpServer   *http.Server
	mux          *http.ServeMux
	BaseURL      *url.URL
	hashes       ch.HashStorage
	quit         chan struct{}
	signalQueue  chan os.Signal
	readerQueue  chan string
	hashingQueue chan ch.Im
	mappingQueue chan ch.ImageHash
}

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
	sqlitePath         string
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
	flag.StringVar(&opts.sqlitePath, "sqlite-path", "tmp.sqlite", "Path to sqlite database to use for matching hashes, substantialy reduces memory usage")
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
	opts.sqlitePath, _ = filepath.Abs(opts.sqlitePath)
	pretty.Logln(opts)
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
	// if _, domainExists := s.ids[ch.Source(domain)]; !domainExists {
	// 	msg := "No IDs belonging to " + domain + "exist on this server"
	// 	log.Println(msg)
	// 	writeJson(w, http.StatusBadRequest, result{Msg: msg})
	// }
	log.Printf("Attempting to associate %s:%s to %s:%s", domain, ID, newDomain, newID)
	found := false
	// for _, hash := range []map[uint64][]string{s.FullAhash, s.FullDhash, s.FullPhash} {
	// 	for i, idlist := range hash {
	// 		if _, found_in_hash := slices.BinarySearch(idlist, domain+":"+ID); found_in_hash {
	// 			found = true
	// 			hash[i] = ch.Insert(idlist, newDomain+":"+newID)
	// 			if _, ok := s.ids[ch.Source(newDomain)]; !ok {
	// 				s.ids[ch.Source(newDomain)] = make(map[string]struct{})
	// 			}
	// 			s.ids[ch.Source(newDomain)][newID] = struct{}{}
	// 		}
	// 	}
	// }
	if found {
		writeJson(w, http.StatusOK, result{Msg: "New ID added"})
	} else {
		writeJson(w, http.StatusOK, result{Msg: "Old ID not found"})
	}
}

type SimpleResult struct {
	Distance int
	IDList   ch.IDList
}

func getSimpleResults(fullResults []ch.Result) []SimpleResult {
	simpleResult := make([]SimpleResult, 0, len(fullResults))

	slices.SortFunc(fullResults, func(a, b ch.Result) int {
		return cmp.Compare(a.Distance, b.Distance) * -1 // Reverses sort
	})

	// Deduplicate IDs
	distance := make(map[int]SimpleResult)

	for _, fullResult := range fullResults {
		simple, ok := distance[fullResult.Distance]
		if !ok {
			simple.IDList = make(ch.IDList)
		}
		for source, ids := range fullResult.IDs {
			for _, id := range ids {
				simple.IDList[source] = ch.Insert(simple.IDList[source], id)
			}
		}
	}

	// turn into array
	for _, sr := range distance {
		simpleResult = append(simpleResult, sr)
	}
	return simpleResult
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
	matches, err := s.hashes.GetMatches([]ch.Hash{{ahash, goimagehash.AHash}, {dhash, goimagehash.DHash}, {phash, goimagehash.PHash}}, max, exactOnly)
	log.Println(err)
	if len(matches) > 0 {
		var msg string = ""
		if err != nil {
			msg = err.Error()
		}
		if simple {
			writeJson(w, http.StatusOK, result{
				Results: getSimpleResults(matches),
				Msg:     msg,
			})
			return
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
	s.hashingQueue <- ch.Im{Im: i, Format: format, ID: ch.ID{Domain: ch.Source(domain), ID: ID}, Path: ""}
	writeJson(w, http.StatusOK, result{Msg: "Success"})
}

func (s *Server) mapper(done func()) {
	defer done()
	for hash := range s.mappingQueue {
		s.hashes.MapHashes(hash)
	}
}

func (s *Server) hasher(workerID int, done func()) {
	defer done()
	for image := range s.hashingQueue {
		start := time.Now()

		hash := ch.HashImage(image)
		if hash.ID.Domain == "" || hash.ID.ID == "" {
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
		log.Printf("Hashing took %v: worker: %v. path: %s %s: %064b id: %s\n", elapsed, workerID, image.Path, hash.Hashes[0].Kind, hash.Hashes[0].Hash, hash.ID)
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

		im := ch.Im{
			Im: i, Format: format,
			ID:   ch.ID{Domain: ch.Source(filepath.Base(filepath.Dir(filepath.Dir(path)))), ID: filepath.Base(filepath.Dir(path))},
			Path: path,
		}
		select {
		case <-s.quit:
			log.Println("Recieved quit")
			return
		case s.hashingQueue <- im:
		default:
		}
	}
}

// EncodeHashes must have a lock to s.hashMutex
func (s *Server) EncodeHashes(format Format) ([]byte, error) {
	var encoder Encoder
	switch format {
	case Msgpack:
		encoder = msgpack.Marshal
	case JSON:
		encoder = json.Marshal
	default:
		return nil, fmt.Errorf("Unknown format: %v", format)
	}
	hashes, err := s.hashes.EncodeHashes()
	if err != nil {
		return nil, err
	}
	return encoder(hashes)
}

// DecodeHashes must have a lock to s.hashMutex
func (s *Server) DecodeHashes(format Format, hashes []byte) error {
	var decoder Decoder
	switch format {
	case Msgpack:
		decoder = msgpack.Unmarshal
	case JSON:
		decoder = json.Unmarshal

	default:
		return fmt.Errorf("Unknown format: %v", format)
	}
	loadedHashes := make(ch.SavedHashes)
	err := decoder(hashes, &loadedHashes)
	if err != nil {
		return err
	}

	return s.hashes.DecodeHashes(loadedHashes)
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
		quit:         make(chan struct{}),
		signalQueue:  make(chan os.Signal, 1),
		readerQueue:  make(chan string, 100),
		hashingQueue: make(chan ch.Im),
		mappingQueue: make(chan ch.ImageHash),
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
	var err error
	fmt.Println("init hashes")
	server.hashes, err = ch.NewMapStorage()
	if err != nil {
		panic(err)
	}

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
		fmt.Printf("Loaded embedded %s hashes\n", format)
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
			fmt.Printf("Loaded hashes from %q %s\n", opts.hashesPath, format)
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
	err = server.httpServer.ListenAndServe()
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
