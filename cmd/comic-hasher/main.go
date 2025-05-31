package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
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
)

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
	memprofile         string
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
	flag.StringVar(&opts.memprofile, "memprofile", "", "Write mem profile to file")
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
			gr.Close()
		}
	} else {
		fmt.Println("Loading saved hashes")
		if f, err := os.Open(opts.hashesPath); err == nil {
			var r io.ReadCloser = f
			if gr, err := gzip.NewReader(f); err == nil {
				r = gr
			} else {
				_, _ = f.Seek(0, io.SeekStart)
			}
			hashes, err = io.ReadAll(r)
			r.Close()
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
	if errors.Is(err, ch.NoHashes) {
		log.Println("No saved hashes to load", loadedHashes, err)
		return loadedHashes
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to decode hashes: %s", err))
	}
	fmt.Printf("Loaded %s hashes\n", format)
	return loadedHashes
}
func saveHashes(opts Opts, hashes *ch.SavedHashes) error {
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
		id := ch.ID{Domain: ch.NewSource(ch.ComicVine), ID: path.IssueID}
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
func printMemStats(m runtime.MemStats) {
	fmt.Printf("Alloc = %v MiB\n", bToKb(m.Alloc))
	fmt.Printf("TotalAlloc = %v MiB\n", bToKb(m.TotalAlloc))
	fmt.Printf("Sys = %v MiB\n", bToKb(m.Sys))
	fmt.Printf("NumGC = %v\n", m.NumGC)
}

func bToKb(b uint64) uint64 {
	return b / 1024 / 1024
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
	if err := server.hashes.DecodeHashes(loadHashes(opts)); err != nil {
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
	if opts.memprofile != "" {
		f, err := os.Create(opts.memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC()    // get up-to-date statistics
		// Lookup("allocs") creates a profile similar to go test -memprofile.
		// Alternatively, use Lookup("heap") for a profile
		// that has inuse_space as the default index.
		m := runtime.MemStats{}
		runtime.ReadMemStats(&m)
		printMemStats(m)
		if err := pprof.Lookup("heap").WriteTo(f, 0); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}

	}
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
