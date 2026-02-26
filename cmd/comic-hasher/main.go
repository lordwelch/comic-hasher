package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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
	"os/signal"
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
	showVersion, fs := registerOptions(&opts)
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

	log.Println("Looking for saved hashes at", hashesPath)
	f, err := os.Open(hashesPath)
	if err == nil {
		var r io.ReadCloser = f
		if gr, err := gzip.NewReader(f); err == nil {
			r = gr
		} else {
			_, _ = f.Seek(0, io.SeekStart)
		}
		hashes, err = io.ReadAll(r)
		_ = r.Close()
		_ = f.Close()
		if err != nil {
			panic(fmt.Sprintf("Failed to load hashes from disk: %s", err))
		}
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			log.Println("Unable to load saved hashes", err)
		}
	}
	if errors.Is(err, os.ErrNotExist) || len(hashes) < 18 {
		log.Println("No saved hashes to load")
	}

	if opts.loadEmbeddedHashes && len(ch.Hashes) != 0 && len(hashes) < 18 {
		log.Println("Loading embedded hashes")
		hashes = ch.Hashes
		if gr, err := gzip.NewReader(bytes.NewReader(ch.Hashes)); err == nil {
			hashes, err = io.ReadAll(gr)
			if err != nil {
				panic(fmt.Sprintf("Failed to read embedded hashes: %s", err))
			}
			gr.Close()
		}
	}

	var (
		format       ch.Format
		loadedHashes *ch.SavedHashes
	)

	for _, format = range []ch.Format{ch.Msgpack, ch.JSON} {
		if loadedHashes, err = ch.DecodeHashes(format, hashes); errors.Is(err, ch.ErrDecodeFail) {
			continue
		}
		break
	}
	if errors.Is(err, ch.ErrNoHashes) || errors.Is(err, ch.ErrDecodeFail) {
		log.Println("No saved hashes to load")
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
		rwg.Go(func() { server.reader(i) })
	}

	log.Println("Init 10 hashers")
	hwg := sync.WaitGroup{}
	for i := range 10 {
		hwg.Go(func() { server.hasher(i) })
	}

	log.Println("Init 1 mapper")
	mwg := sync.WaitGroup{}
	mwg.Go(func() { server.mapper(1) })

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
	dcwg.Go(func() {
		downloadProcessor(chdb, opts, finishedDownloadQueue, server)
	})

	if opts.cv.enabled {
		dwg.Go(func() {
			cvdownloader := cv.NewCVDownloader(server.Context, bufPool, opts.onlyHashNewIDs, server.hashes.GetIDs, chdb, filepath.Join(opts.path, "comicvine"), opts.cv.APIKey, opts.cv.images, opts.keepDownloaded, opts.cv.hashDownloaded, finishedDownloadQueue)
			cv.DownloadCovers(cvdownloader)
			for {
				select {
				case <-time.After(2 * time.Hour):
					cv.DownloadCovers(cvdownloader)
				case <-server.Context.Done():
					return
				}
			}
		})
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
	log.Println("If you press Ctrl+C after this point the saved hashes will be corrupted")
	signal.Stop(server.signalQueue)
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
