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
	"runtime/debug"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/disintegration/imaging"
	"github.com/kr/pretty"

	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/comic-hasher/cv"
	"gitea.narnian.us/lordwelch/goimagehash"
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

var bufPool = &sync.Pool{
	New: func() any {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation:
		return new(bytes.Buffer)
	},
}

type Storage int

const (
	Map = iota + 1
	BasicMap
	Sqlite
	Sqlite3
	VPTree
)

var storageNames = map[Storage]string{
	Map:      "map",
	BasicMap: "basicmap",
	Sqlite:   "sqlite",
	Sqlite3:  "sqlite3",
	VPTree:   "vptree",
}

var storageValues = map[string]Storage{
	"map":      Map,
	"basicmap": BasicMap,
	"sqlite":   Sqlite,
	"sqlite3":  Sqlite3,
	"vptree":   VPTree,
}

func (f Storage) String() string {
	if name, known := storageNames[f]; known {
		return name
	}
	return "Unknown"
}

func (f *Storage) Set(s string) error {
	if storage, known := storageValues[strings.ToLower(s)]; known {
		*f = storage
	} else {
		return fmt.Errorf("Unknown storage type: %d", f)
	}
	return nil
}

type CVOpts struct {
	downloadCovers bool
	APIKey         string
	path           string
	thumbOnly      bool
	originalOnly   bool
	hashDownloaded bool
	keepDownloaded bool
}
type Opts struct {
	cpuprofile         string
	coverPath          string
	sqlitePath         string
	loadEmbeddedHashes bool
	saveEmbeddedHashes bool
	format             ch.Format
	hashesPath         string
	storageType        Storage
	onlyHashNewIDs     bool
	deleteHashedImages bool
	path               string
	version            string
	addr               string
	debugPort          string

	cv CVOpts
}

func main() {
	version := "devel"
	buildInfo, buildInfoFound := debug.ReadBuildInfo()
	versionInfo := strings.SplitN(buildInfo.Main.Version, "-", 3)
	if buildInfoFound {
		switch len(versionInfo) {
		default:
			version = buildInfo.Main.Version
		case 2:
			version = versionInfo[1]
		case 3:
			version = versionInfo[0] + "-" + versionInfo[2]
		}
	}
	opts := Opts{format: ch.Msgpack, storageType: BasicMap, version: version} // flag is weird
	wd, err := os.Getwd()
	fmt.Println(err)
	if err != nil {
		wd = "comic-hasher"
	} else {
		wd = filepath.Join(wd, "comic-hasher")
	}
	flag.StringVar(&opts.cpuprofile, "cpuprofile", "", "Write cpu profile to file")
	flag.StringVar(&opts.addr, "listen", ":8080", "Address to listen on")
	flag.StringVar(&opts.debugPort, "debug-port", "", "Port to listen to for debug info")

	flag.StringVar(&opts.path, "path", wd, "Path for comic-hasher to store files")
	flag.StringVar(&opts.coverPath, "cover-path", "", "Path to local covers to add to hash database. Must be in the form '{cover-path}/{domain}/{id}/*' eg for --cover-path /covers it should look like /covers/comicvine.gamespot.com/10000/image.gif")
	flag.StringVar(&opts.sqlitePath, "sqlite-path", "", fmt.Sprintf("Path to sqlite database to use for matching hashes, substantialy reduces memory usage (default %v)", filepath.Join(wd, "tmp.sqlite")))
	flag.BoolVar(&opts.loadEmbeddedHashes, "use-embedded-hashes", true, "Use hashes embedded in the application as a starting point")
	flag.BoolVar(&opts.saveEmbeddedHashes, "save-embedded-hashes", false, "Save hashes even if we loaded the embedded hashes")
	flag.StringVar(&opts.hashesPath, "hashes", "", fmt.Sprintf("Path to optionally gziped hashes in msgpack or json format. You must disable embedded hashes to use this option (default %v)", filepath.Join(wd, "hashes.gz")))
	flag.Var(&opts.format, "save-format", "Specify the format to export hashes to (json, msgpack)")
	flag.Var(&opts.storageType, "storage-type", "Specify the storage type used internally to search hashes (sqlite,sqlite3,map,basicmap,vptree)")
	flag.BoolVar(&opts.onlyHashNewIDs, "only-hash-new-ids", true, "Only hashes new covers from CV/local path (Note: If there are multiple covers for the same ID they may get queued at the same time and hashed on the first run, implies -cv-thumb-only if -delete-hashed-images is true or -cv-keep-downloaded is false)")
	flag.BoolVar(&opts.deleteHashedImages, "delete-hashed-images", false, "Deletes downloaded images after hashing them, useful to save space, paths are recorded in ch.sqlite")

	flag.BoolVar(&opts.cv.downloadCovers, "cv-dl-covers", false, "Downloads all covers from ComicVine and adds them to the server")
	flag.StringVar(&opts.cv.APIKey, "cv-api-key", "", "API Key to use to access the ComicVine API")
	flag.StringVar(&opts.cv.path, "cv-path", "", fmt.Sprintf("Path to store ComicVine data in (default %v)", filepath.Join(wd, "comicvine")))
	flag.BoolVar(&opts.cv.thumbOnly, "cv-thumb-only", true, "Only downloads the thumbnail image from comicvine, when false sets -only-hash-new-ids=false")
	flag.BoolVar(&opts.cv.originalOnly, "cv-original-only", true, "Only downloads the original image from comicvine, when false sets -only-hash-new-ids=false")
	flag.BoolVar(&opts.cv.hashDownloaded, "cv-hash-downloaded", true, "Hash already downloaded images")
	flag.BoolVar(&opts.cv.keepDownloaded, "cv-keep-downloaded", true, "Keep downloaded images. When set to false does not ever write to the filesystem, a crash or exiting can mean some images need to be re-downloaded")
	flag.Parse()

	if opts.debugPort != "" {
		go func() {
			log.Println(http.ListenAndServe("127.0.0.1:"+opts.debugPort, nil))
		}()
	}
	if opts.coverPath != "" {
		_, err := os.Stat(opts.coverPath)
		if err != nil {
			panic(err)
		}
	}
	if opts.cv.downloadCovers {
		if opts.cv.APIKey == "" {
			log.Fatal("No ComicVine API Key provided")
		}
	}
	opts.path, _ = filepath.Abs(opts.path)
	if opts.hashesPath == "" {
		opts.hashesPath = filepath.Join(opts.path, "hashes.gz")
	}
	opts.hashesPath, _ = filepath.Abs(opts.hashesPath)
	if opts.sqlitePath == "" {
		opts.sqlitePath = filepath.Join(opts.path, "tmp.sqlite")
	}
	opts.sqlitePath, _ = filepath.Abs(opts.sqlitePath)
	if opts.cv.path == "" {
		opts.cv.path = filepath.Join(opts.path, "comicvine")
	}
	opts.cv.path, _ = filepath.Abs(opts.cv.path)
	pretty.Log(opts)

	// TODO: Fix options

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
	idToDistance := make(map[ch.ID]int)

	for _, fullResult := range fullResults {
		for domain, idlist := range fullResult.IDs {
			for _, idStr := range idlist {
				id := ch.ID{
					Domain: domain,
					ID:     idStr,
				}
				if distance, ok := idToDistance[id]; !ok || fullResult.Distance < distance {
					idToDistance[id] = fullResult.Distance
				}
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
		sr.Distance = distance
		sr.IDList[id.Domain] = append(sr.IDList[id.Domain], id.ID)
		distanceMap[distance] = sr
	}

	// turn into array
	for _, sr := range distanceMap {
		simpleResult = append(simpleResult, sr)
	}
	slices.SortFunc(simpleResult, func(a, b SimpleResult) int {
		return cmp.Compare(a.Distance, b.Distance)
	})
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
		hashes    []ch.Hash
	)

	if ahash, err = strconv.ParseUint(ahashStr, 16, 64); err != nil && ahashStr != "" {
		log.Printf("could not parse ahash: %s", ahashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if ahash > 0 {
		hashes = append(hashes, ch.Hash{ahash, goimagehash.AHash})
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		log.Printf("could not parse dhash: %s", dhashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if dhash > 0 {
		hashes = append(hashes, ch.Hash{dhash, goimagehash.DHash})
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		log.Printf("could not parse phash: %s", phashStr)
		writeJson(w, http.StatusBadRequest, result{Msg: "hash parse failed"})
		return
	}
	if phash > 0 {
		hashes = append(hashes, ch.Hash{phash, goimagehash.PHash})
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
	w.WriteHeader(http.StatusNotImplemented)
	return
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

func signalHandler(s *Server) {
	select {
	case sig := <-s.signalQueue:
		log.Printf("Signal: %v\n", sig)
		s.cancel()
	case <-s.Context.Done():
		log.Println("Recieved quit: Attempting to shutdown gracefully")
	}
	err := s.httpServer.Shutdown(context.TODO())
	log.Println("Err:", err)
}

func initializeStorage(opts Opts) (ch.HashStorage, error) {
	switch opts.storageType {
	case Map:
		return ch.NewMapStorage()
	case BasicMap:
		return ch.NewBasicMapStorage()
	case Sqlite:
		return ch.NewSqliteStorage("sqlite", opts.sqlitePath)
	case Sqlite3:
		return ch.NewSqliteStorage("sqlite3", opts.sqlitePath)
	case VPTree:
		return ch.NewVPStorage()
	}
	return nil, errors.New("Unknown storage type provided")
}

func loadHashes(opts Opts) *ch.SavedHashes {
	var hashes []byte
	if opts.loadEmbeddedHashes && len(ch.Hashes) != 0 {
		fmt.Println("Loading embedded hashes")
		hashes = ch.Hashes
		if gr, err := gzip.NewReader(bytes.NewReader(ch.Hashes)); err == nil {
			hashes, err = io.ReadAll(gr)
			if err != nil {
				panic(fmt.Sprintf("Failed to read embedded hashes: %s", err))
			}
		}
	} else {
		fmt.Println("Loading saved hashes")
		if f, err := os.Open(opts.hashesPath); err == nil {
			var buf io.Reader = f
			if gr, err := gzip.NewReader(buf); err == nil {
				buf = bufio.NewReader(gr)
			} else {
				_, _ = f.Seek(0, io.SeekStart)
			}
			hashes, err = io.ReadAll(buf)
			f.Close()
			if err != nil {
				panic(fmt.Sprintf("Failed to load hashes from disk: %s", err))
			}
		} else {
			if errors.Is(err, os.ErrNotExist) {
				log.Println("No saved hashes to load")
			} else {
				log.Println("Unable to load saved hashes", err)
			}
			return nil
		}
	}

	var (
		format       ch.Format
		loadedHashes *ch.SavedHashes
		err          error
	)
	for _, format = range []ch.Format{ch.Msgpack, ch.JSON} {
		if loadedHashes, err = ch.DecodeHashes(format, hashes); errors.Is(err, ch.DecodeError) {
			continue
		}
		break
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to decode hashes: %s", err))
	}
	fmt.Printf("Loaded %s hashes\n", format)
	return loadedHashes
}
func saveHashes(opts Opts, hashes ch.SavedHashes) error {
	if opts.loadEmbeddedHashes && !opts.saveEmbeddedHashes {
		return errors.New("refusing to save embedded hashes")
	}

	encodedHashes, err := ch.EncodeHashes(hashes, opts.format)
	if err != nil {
		return fmt.Errorf("unable to encode hashes as %v: %w", opts.format, err)
	}
	f, err := os.Create(opts.hashesPath)
	if err != nil {
		return fmt.Errorf("unabled to save hashes: %w", err)
	}

	gzw := gzip.NewWriter(f)

	if _, err = gzw.Write(encodedHashes); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}

	if err = gzw.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}

	if err = f.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}
	log.Println("Successfully saved hashes")
	return nil
}

func downloadProcessor(chdb ch.CHDB, opts Opts, imagePaths chan cv.Download, server Server) {
	defer func() {
		log.Println("Download Processor completed")
		close(server.hashingQueue)
	}()
	for path := range imagePaths {
		id := ch.ID{Domain: ch.ComicVine, ID: path.IssueID}
		if opts.onlyHashNewIDs && len(server.hashes.GetIDs(id)) > 0 {
			continue
		}

		if chdb.PathHashed(path.Dest) {
			continue
		}
		var (
			file io.ReadCloser
			err  error
		)
		if path.Image == nil {
			file, err = os.OpenFile(path.Dest, os.O_RDWR, 0666)
			if err != nil {
				panic(err)
			}
		} else {
			file = io.NopCloser(path.Image)
		}
		i, format, err := image.Decode(bufio.NewReader(file))
		file.Close()
		if path.Image != nil && path.Image.Cap() < 10*1024*1024 {
			bufPool.Put(path.Image)
		}
		if err != nil {
			if len(path.URL) > 0 {
				log.Println("Reading image failed, adding to known bad urls:", path.URL, err)
				chdb.AddURL(path.URL)
			} else {
				log.Println("Reading image failed", path.Dest, err)
			}
			continue // skip this image
		}
		chdb.AddPath(path.Dest) // Add to db and remove file if opts.deleteHashedImages is true

		im := ch.Im{
			Im:      i,
			Format:  format,
			ID:      id,
			NewOnly: opts.onlyHashNewIDs,
		}
		server.hashingQueue <- im
	}
}

type CHMux struct {
	version string
	*http.ServeMux
}

func (CHM *CHMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Comic-Hasher "+CHM.version)
	CHM.ServeMux.ServeHTTP(w, r)
}
func startServer(opts Opts) {
	imaging.SetMaxProcs(2)
	if opts.cpuprofile != "" {
		f, err := os.Create(opts.cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	mux := &CHMux{opts.version, &http.ServeMux{}}

	ctx, cancel := context.WithCancel(context.Background())
	server := Server{
		Context:      ctx,
		cancel:       cancel,
		signalQueue:  make(chan os.Signal, 1),
		readerQueue:  make(chan string, 1),
		hashingQueue: make(chan ch.Im, 1),
		mappingQueue: make(chan ch.ImageHash, 1),
		mux:          mux,
		httpServer: &http.Server{
			Addr:           opts.addr,
			Handler:        mux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
		onlyHashNewIDs: opts.onlyHashNewIDs,
		version:        opts.version,
	}
	Notify(server.signalQueue)
	var err error
	log.Println("Init hashes")
	server.hashes, err = initializeStorage(opts)
	if err != nil {
		panic(err)
	}

	log.Println("Init handlers")
	server.setupAppHandlers()

	log.Println("Init 10 readers")
	rwg := sync.WaitGroup{}
	for i := range 10 {
		rwg.Add(1)
		go server.reader(i, func(i int) { log.Println("Reader", i, "completed"); rwg.Done() })
	}

	log.Println("Init 10 hashers")
	hwg := sync.WaitGroup{}
	for i := range 10 {
		hwg.Add(1)
		go server.hasher(i, func(i int) { log.Println("Hasher", i, "completed"); hwg.Done() })
	}

	log.Println("Init 1 mapper")
	mwg := sync.WaitGroup{}
	mwg.Add(1)
	go server.mapper(func() { log.Println("Mapper 0 completed"); mwg.Done() })

	// DecodeHashes would normally need a write lock
	// nothing else has been started yet so we don't need one
	if err := server.hashes.DecodeHashes(*loadHashes(opts)); err != nil {
		panic(err)
	}

	server.HashLocalImages(opts)
	chdb, err := ch.OpenCHDBBolt(filepath.Join(opts.path, "chdb.bolt"), opts.cv.path, opts.deleteHashedImages)
	if err != nil {
		panic(err)
	}

	log.Println("Init downloaders")
	dwg := sync.WaitGroup{}
	dcwg := sync.WaitGroup{}
	finishedDownloadQueue := make(chan cv.Download, 1)
	dcwg.Add(1)
	go func() {
		defer dcwg.Done()
		downloadProcessor(chdb, opts, finishedDownloadQueue, server)
	}()

	if opts.cv.downloadCovers {
		dwg.Add(1)
		imageTypes := []string{}
		if opts.cv.thumbOnly {
			imageTypes = append(imageTypes, "thumb_url")
		} else if opts.cv.originalOnly {
			imageTypes = append(imageTypes, "original_url")
		}
		cvdownloader := cv.NewCVDownloader(server.Context, bufPool, opts.onlyHashNewIDs, server.hashes.GetIDs, chdb, opts.cv.path, opts.cv.APIKey, imageTypes, opts.cv.keepDownloaded, opts.cv.hashDownloaded, finishedDownloadQueue)
		go func() {
			defer dwg.Done()
			cv.DownloadCovers(cvdownloader)
		f:
			for {
				select {
				case <-time.After(2 * time.Hour):
					cv.DownloadCovers(cvdownloader)
				case <-server.Context.Done():
					break f
				}
			}
		}()
	}

	go signalHandler(&server)
	log.Println("Listening on ", server.httpServer.Addr)
	err = server.httpServer.ListenAndServe()
	if err != nil {
		log.Println(err)
	}

	close(server.readerQueue)
	log.Println("waiting on readers")
	rwg.Wait()
	for dw := range server.readerQueue {
		fmt.Println("Skipping read", dw)
	}

	log.Println("waiting on downloaders")
	dwg.Wait() // Downloaders send to finishedDownloadQueue which sends to server.hashingQueue

	log.Println("waiting on downloader")
	close(finishedDownloadQueue)
	dcwg.Wait() // Wait for the download processor to finish
	for dw := range finishedDownloadQueue {
		fmt.Println("Skipping download", dw.IssueID)
	}

	// close(server.hashingQueue) // Closed by downloadProcessor
	log.Println("waiting on hashers")
	hwg.Wait()
	for dw := range server.hashingQueue {
		fmt.Println("Skipping hashing", dw.ID)
	}

	close(server.mappingQueue)
	log.Println("waiting on mapper")
	mwg.Wait()
	for dw := range server.mappingQueue {
		fmt.Println("Skipping mapping", dw.ID)
	}

	close(server.signalQueue)
	for dw := range server.signalQueue {
		fmt.Println("Skipping", dw)
	}

	_ = chdb.Close()

	// server.EncodeHashes would normally need a read lock
	// the server has been stopped so it's not needed here
	hashes, err := server.hashes.EncodeHashes()
	if err != nil {
		panic(fmt.Errorf("Failed to save hashes: %w", err))
	}
	if err = saveHashes(opts, hashes); err != nil {
		panic(err)
	}
}
