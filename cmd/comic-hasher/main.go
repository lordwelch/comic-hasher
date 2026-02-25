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
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/disintegration/imaging"
	"github.com/kr/pretty"

	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/comic-hasher/cv"
	"gitea.narnian.us/lordwelch/comic-hasher/storage"
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
		return fmt.Errorf("unknown storage type: %d", f)
	}
	return nil
}

type CVOpts struct {
	enabled        bool
	APIKey         string
	images         cv.Images
	hashDownloaded bool
}
type Opts struct {
	cpuprofile         string
	memprofile         string
	coverPath          string
	loadEmbeddedHashes bool
	saveEmbeddedHashes bool
	format             ch.Format
	storageType        Storage
	onlyHashNewIDs     bool
	deleteHashedImages bool
	keepDownloaded     bool
	path               string
	version            string
	addr               string
	debugPort          string

	cv CVOpts
}

func isZeroValue(currentFlag *flag.Flag, value string) (ok bool, err error) {
	// Build a zero value of the flag's Value type, and see if the
	// result of calling its String method equals the value passed in.
	// This works unless the Value type is itself an interface type.
	typ := reflect.TypeOf(currentFlag.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Pointer {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	// Catch panics calling the String method, which shouldn't prevent the
	// usage message from being printed, but that we should report to the
	// user so that they know to fix their code.
	defer func() {
		if e := recover(); e != nil {
			if typ.Kind() == reflect.Pointer {
				typ = typ.Elem()
			}
			err = fmt.Errorf("panic calling String method on zero %v for flag %s: %v", typ, currentFlag.Name, e)
		}
	}()
	return value == z.Interface().(flag.Value).String(), nil
}

func Usage(f *flag.FlagSet) {
	fmt.Fprintf(f.Output(), "Usage of %s:\n", f.Name())
	var isZeroValueErrs []error
	helpItems := make(map[string][]string)
	f.VisitAll(func(currentFlag *flag.Flag) {
		var b strings.Builder
		fmt.Fprintf(&b, "  -%s", currentFlag.Name) // Two spaces before -; see next two comments.
		name, usage := flag.UnquoteUsage(currentFlag)
		if len(name) > 0 {
			b.WriteString(" ")
			b.WriteString(name)
		}
		// Boolean flags of one ASCII letter are so common we
		// treat them specially, putting their usage on the same line.
		if b.Len() <= 4 { // space, space, '-', 'x'.
			b.WriteString("\t")
		} else {
			// Four spaces before the tab triggers good alignment
			// for both 4- and 8-space tab stops.
			b.WriteString("\n    \t")
		}
		b.WriteString(strings.ReplaceAll(usage, "\n", "\n    \t"))

		// Print the default value only if it differs to the zero value
		// for this flag type.
		if isZero, err := isZeroValue(currentFlag, currentFlag.DefValue); err != nil {
			isZeroValueErrs = append(isZeroValueErrs, err)
		} else if !isZero {
			if reflect.TypeOf(currentFlag.Value).Name() == "stringValue" {
				// put quotes on the value
				fmt.Fprintf(&b, " (default %q)", currentFlag.DefValue)
			} else {
				fmt.Fprintf(&b, " (default %v)", currentFlag.DefValue)
			}
		}
		helpItems[groups[currentFlag.Name]] = append(helpItems[groups[currentFlag.Name]], b.String())
	})
	toTitle := cases.Title(language.English)
	for _, group := range groupOrder {
		groupItems := helpItems[group]
		if len(groupItems) == 0 {
			continue
		}
		slices.SortFunc(groupItems, func(a, b string) int {
			return strings.Compare(strings.ToLower(a), strings.ToLower(b))
		})
		if group != "" {
			fmt.Fprintf(f.Output(), "\n%s:\n", toTitle.String(group))
		}
		for _, item := range helpItems[group] {
			fmt.Fprintln(f.Output(), item)
		}
	}
	// If calling String on any zero flag.Values triggered a panic, print
	// the messages after the full set of defaults so that the programmer
	// knows to fix the panic.
	if errs := isZeroValueErrs; len(errs) > 0 {
		fmt.Fprintln(f.Output())
		for _, err := range errs {
			fmt.Fprintln(f.Output(), err)
		}
	}
}

var (
	groupOrder = []string{"", "file", "hash", "comic vine", "debug"}
	groups     = map[string]string{
		"use-embedded-hashes":  "file",
		"save-embedded-hashes": "file",
		"save-format":          "file",
		"storage-type":         "hash",
		"only-hash-new-ids":    "hash",
		"keep-downloaded":      "download",
		"hash-downloaded":      "download",
		"cv":                   "comic vine",
		"cv-api-key":           "comic vine",
		"cv-images":            "comic vine",
		"cpuprofile":           "debug",
		"memprofile":           "debug",
		"debug-port":           "debug",
	}
)

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
	opts := Opts{
		format: ch.Msgpack, storageType: BasicMap, version: version,
		cv: CVOpts{
			images: cv.Images{"thumb": {}},
		},
	}
	wd := "comic-hasher"
	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)
	fs.Usage = func() { Usage(fs) }
	fs.StringVar(&opts.addr, "listen", ":8080", "Address to listen on")
	fs.StringVar(&opts.path, "path", "./"+wd, "Path for comic-hasher to store files")
	fs.StringVar(&opts.coverPath, "cover-path", "", "`Path` to local covers to add to hash database.\nMust be in the form '{cover-path}/{domain}/{id}/*'\neg for --cover-path /covers it should look like /covers/comicvine.gamespot.com/10000/image.gif")

	fs.BoolVar(&opts.loadEmbeddedHashes, "use-embedded-hashes", true, "Use hashes embedded in the application as a starting point")
	fs.BoolVar(&opts.saveEmbeddedHashes, "save-embedded-hashes", false, "Save hashes even if we loaded the embedded hashes")
	fs.Var(&opts.format, "save-format", "Specify the `format` to save hashes in (json, msgpack)")

	fs.Var(&opts.storageType, "storage-type", "Specify the `storage type` used internally to search hashes\n(Sqlite,Sqlite3,Map,BasicMap,VPTree)")

	fs.BoolVar(&opts.onlyHashNewIDs, "only-hash-new-ids", true, "Only hashes new covers\n\nIf multiple image types (-cv-images) are selected more than 1 may get through")
	fs.BoolVar(&opts.keepDownloaded, "keep-downloaded", false, "Keep newly downloaded images.\nWhen set to false does not ever write images to the filesystem\nA crash or exiting during downloading can mean some images need to be re-downloaded")
	fs.BoolVar(&opts.cv.hashDownloaded, "hash-downloaded", true, "Hash already downloaded images")

	fs.BoolVar(&opts.cv.enabled, "cv", false, "Enabled automatically downloading covers from ComicVine to add to the database\n(averages 1 api call per hour once cought up)")
	fs.StringVar(&opts.cv.APIKey, "cv-api-key", "", "API `Key` to use to access the ComicVine API")
	fs.Var(&opts.cv.images, "cv-images", "Download the selected `image types` from comicvine\n(Original,Thumb,Icon,Medium,Screen,ScreenLarge,Small,Super,Tiny)")

	fs.StringVar(&opts.cpuprofile, "cpuprofile", "", "Write cpu profile to `file`")
	fs.StringVar(&opts.memprofile, "memprofile", "", "Write mem profile to `file` after loading hashes")
	fs.StringVar(&opts.debugPort, "debug-port", "", "`Port` to listen to for debug info")
	showVersion := fs.Bool("version", false, "Show version and quit")
	fs.BoolVar(showVersion, "V", false, "Show version and quit")
	// showHelp := fs.Bool("help", false, "Show help quit")
	// fs.BoolVar(showHelp, "h", false, "Show help quit")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		Usage(fs)
		os.Exit(1)
	}

	if *showVersion {
		fmt.Println("comic-hasher version:", opts.version)
		os.Exit(0)
	}

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
	if opts.cv.enabled {
		if opts.cv.APIKey == "" {
			log.Fatal("No ComicVine API Key provided")
		}
	}

	opts.path, _ = filepath.Abs(opts.path)
	pretty.Log(opts)

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
		return storage.NewMapStorage()
	case BasicMap:
		return storage.NewBasicMapStorage()
	case Sqlite:
		return storage.NewSqliteStorage("sqlite", filepath.Join(opts.path, "tmp.sqlite"))
	case Sqlite3:
		return storage.NewSqliteStorage("sqlite3", filepath.Join(opts.path, "tmp.sqlite"))
	case VPTree:
		return storage.NewVPStorage()
	}
	return nil, errors.New("unknown storage type provided")
}

const hashesFilename = "hashes.gz"

func loadHashes(opts Opts) *ch.SavedHashes {
	hashesPath := filepath.Join(opts.path, hashesFilename)
	var hashes []byte
	if opts.loadEmbeddedHashes && len(ch.Hashes) != 0 {
		log.Println("Loading embedded hashes")
		hashes = ch.Hashes
		if gr, err := gzip.NewReader(bytes.NewReader(ch.Hashes)); err == nil {
			hashes, err = io.ReadAll(gr)
			if err != nil {
				panic(fmt.Sprintf("Failed to read embedded hashes: %s", err))
			}
			gr.Close()
		}
	} else {
		log.Println("Loading saved hashes")
		if f, err := os.Open(hashesPath); err == nil {
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
				log.Println("No saved hashes to load at", hashesPath)
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
		if loadedHashes, err = ch.DecodeHashes(format, hashes); errors.Is(err, ch.ErrDecodeFail) {
			continue
		}
		break
	}
	if errors.Is(err, ch.ErrNoHashes) {
		log.Println("No saved hashes to load", loadedHashes, err)
		return loadedHashes
	}
	if err != nil {
		log.Panicf("Failed to decode hashes: %s", err)
	}
	log.Printf("Loaded %s hashes\n", format)
	return loadedHashes
}

func saveHashes(opts Opts, hashes *ch.SavedHashes) error {
	if opts.loadEmbeddedHashes && !opts.saveEmbeddedHashes {
		return errors.New("refusing to save embedded hashes")
	}
	if len(hashes.Hashes) < 1 {
		log.Println("Refusing to write empty hashes")
		return nil
	}

	hashesPath := filepath.Join(opts.path, hashesFilename)

	encodedHashes, err := ch.EncodeHashes(hashes, opts.format)
	if err != nil {
		return fmt.Errorf("unable to encode hashes as %v: %w", opts.format, err)
	}
	f, err := os.Create(hashesPath)
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
	log.Println("Hashes saved", len(hashes.Hashes))
	log.Println("ID lists saved", len(hashes.IDs))
	log.Println("Successfully Saved V2 hashes")
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
			file, err = os.OpenFile(path.Dest, os.O_RDWR, 0o666)
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

	server.HashLocalImages(opts.coverPath)
	chdb, err := ch.OpenCHDBBolt(opts.path, opts.deleteHashedImages)
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

	if opts.cv.enabled {
		dwg.Add(1)
		cvdownloader := cv.NewCVDownloader(server.Context, bufPool, opts.onlyHashNewIDs, server.hashes.GetIDs, chdb, filepath.Join(opts.path, "comicvine"), opts.cv.APIKey, opts.cv.images, opts.keepDownloaded, opts.cv.hashDownloaded, finishedDownloadQueue)
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
	if opts.memprofile != "" {
		f, err := os.Create(opts.memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC()    // get up-to-date statistics
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
	log.Println("Listening on ", server.httpServer.Addr)

	close(server.readerQueue)
	log.Println("waiting on readers")
	rwg.Wait()
	for dw := range server.readerQueue {
		log.Println("Skipping read", dw)
	}

	log.Println("waiting on downloaders")
	dwg.Wait() // Downloaders send to finishedDownloadQueue which sends to server.hashingQueue

	log.Println("waiting on downloader")
	close(finishedDownloadQueue)
	dcwg.Wait() // Wait for the download processor to finish
	for dw := range finishedDownloadQueue {
		log.Println("Skipping download", dw.IssueID)
	}

	// close(server.hashingQueue) // Closed by downloadProcessor
	log.Println("waiting on hashers")
	hwg.Wait()
	for dw := range server.hashingQueue {
		log.Println("Skipping hashing", dw.ID)
	}

	close(server.mappingQueue)
	log.Println("waiting on mapper")
	mwg.Wait()
	for dw := range server.mappingQueue {
		log.Println("Skipping mapping", dw.ID)
	}

	close(server.signalQueue)
	for dw := range server.signalQueue {
		log.Println("Skipping", dw)
	}

	_ = chdb.Close()

	// server.EncodeHashes would normally need a read lock
	// the server has been stopped so it's not needed here
	hashes, err := server.hashes.EncodeHashes()
	if err != nil {
		log.Panicf("Failed to save hashes: %v", err)
	}
	if err = saveHashes(opts, hashes); err != nil {
		log.Panic(err)
	}
}
