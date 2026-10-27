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

	"gitea.narnian.us/lordwelch/comic-hasher/ch"
	"gitea.narnian.us/lordwelch/comic-hasher/cv"
	"gitea.narnian.us/lordwelch/comic-hasher/download"
	"gitea.narnian.us/lordwelch/comic-hasher/log"
	"gitea.narnian.us/lordwelch/comic-hasher/metron"
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

var Version string

func main() {
	Version = "devel"
	buildInfo, buildInfoFound := debug.ReadBuildInfo()
	versionInfo := strings.SplitN(buildInfo.Main.Version, "-", 3)
	if buildInfoFound {
		switch len(versionInfo) {
		default:
			Version = buildInfo.Main.Version
		case 2:
			Version = versionInfo[1]
		case 3:
			Version = versionInfo[0] + "-" + versionInfo[2]
		}
	}
	opts := Opts{
		storageType: BasicMap, version: Version,
		cv: CVOpts{
			images: cv.Images{"thumb": {}},
		},
		// logLevels: LogLevels{},
	}
	showVersion, fs := registerOptions(&opts)
	err := fs.Parse(os.Args[1:])
	opts.cv.images.Get()
	opts.logLevels.Get()
	if err != nil {
		Usage(fs)
		os.Exit(1)
	}

	if *showVersion {
		fmt.Println("comic-hasher version:", opts.version)
		os.Exit(0)
	}
	download.Client = &http.Client{Transport: download.RT("Comic-Hasher/" + opts.version)}

	if opts.debugPort != "" {
		go func() {
			log.Println(log.Standard, http.ListenAndServe("127.0.0.1:"+opts.debugPort, nil))
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
			log.Println(log.Fatal, "No ComicVine API Key provided")
			os.Exit(1)
		}
	}

	opts.path, _ = filepath.Abs(opts.path)
	log.Println(log.Standard, pretty.Sprint(opts))

	startServer(opts)
}

func signalHandler(s *ch.Server, signalQueue <-chan os.Signal) {
	select {
	case sig := <-signalQueue:
		log.Log(log.Verbose, "Signal: %v\n", sig)
	case <-s.Context.Done():
		log.Log(log.Standard, "Recieved quit: Attempting to shutdown gracefully")
	}
	err := s.Shutdown()
	log.Println(log.Fatal, "Shutting down server Err:", err)
}

func initializeStorage(opts Opts) (ch.HashStorage, error) {
	switch opts.storageType {
	// case Map:
	// 	return storage.NewMapStorage()
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

func loadHashes(opts Opts) *ch.SavedHashesV3 {
	hashesPath := filepath.Join(opts.path, hashesFilename)
	var hashReader io.Reader

	log.Println(log.Verbose, "Looking for saved hashes at", hashesPath)
	f, err := os.Open(hashesPath)
	if err == nil {
		defer f.Close()
		var r io.ReadCloser = f
		if gr, err := gzip.NewReader(f); err == nil {
			r = gr
			defer gr.Close()
		} else {
			_, _ = f.Seek(0, io.SeekStart)
		}
		log.Println(log.Standard, "Loading saved hashes from", hashesPath)
		// We don't read everything here because we want some of these to be separate allocations
		// And we don't want duplicate allocations
		hashReader = bufio.NewReader(r)
		if err != nil {
			log.Println(log.Fatal, "Failed to load hashes from disk:", err)
			os.Exit(1)
		}
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			log.Println(log.Standard, "Unable to load saved hashes", err)
		}
	}
	if errors.Is(err, os.ErrNotExist) || hashReader == nil { // TODO: fix this. Previously we verified a minimum length of the file
		log.Println(log.Standard, "No saved hashes to load")
	}

	if opts.loadEmbeddedHashes && len(ch.Hashes) != 0 && hashReader == nil {
		log.Println(log.Standard, "Loading embedded hashes")
		hashReader = bytes.NewReader(ch.Hashes)
		if gr, err := gzip.NewReader(bytes.NewReader(ch.Hashes)); err == nil {
			hashReader = gr
			defer gr.Close()
		}
	}

	var loadedHashes *ch.SavedHashesV3
	loadedHashes, err = ch.DecodeHashesV3(hashReader)
	if errors.Is(err, ch.ErrNoHashes) || errors.Is(err, ch.ErrDecodeFail) {
		log.Println(log.Verbose, "No saved hashes to load")
		return loadedHashes
	}
	if err != nil {
		log.Println(log.Fatal, "Failed to decode hashes:", err)
		os.Exit(1)
	}
	log.Println(log.Verbose, "Hashes loaded   ", log.FormatInt(loadedHashes.AHashCount+loadedHashes.DHashCount+loadedHashes.PHashCount))
	log.Println(log.Verbose, "IDs loaded      ", log.FormatInt(loadedHashes.IDCount))
	log.Println(log.Verbose, "ID groups loaded", log.FormatInt(loadedHashes.GroupCount))
	log.Println(log.Debug, "Hashes are consistent:", loadedHashes.AHashCount == loadedHashes.DHashCount && loadedHashes.AHashCount == loadedHashes.PHashCount)
	log.Println(log.Debug, "Hashes match IDs:", loadedHashes.AHashCount == loadedHashes.IDCount)
	log.Println(log.Verbose, "Successfully Loaded V3 hashes")

	return loadedHashes
}

func saveHashes(opts Opts, hashes *ch.SavedHashesV3) error {
	if opts.loadEmbeddedHashes && !opts.saveEmbeddedHashes {
		return errors.New("refusing to save embedded hashes")
	}
	if len(hashes.AHashes)+len(hashes.DHashes)+len(hashes.PHashes) < 1 {
		log.Println(log.Standard, "Refusing to write empty hashes")
		return nil
	}

	hashesPath := filepath.Join(opts.path, hashesFilename)

	f, err := os.Create(hashesPath)
	if err != nil {
		return fmt.Errorf("unabled to save hashes: %w", err)
	}

	gzw := gzip.NewWriter(f)

	err = ch.EncodeHashesV3(hashes, gzw)
	if err != nil {
		return fmt.Errorf("unable to encode hashes: %w", err)
	}
	// if _, err = gzw.Write(encodedHashes); err != nil {
	// 	return fmt.Errorf("failed to write hashes: %w", err)
	// }

	if err = gzw.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}

	if err = f.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}
	log.Println(log.Verbose, "Hashes saved", log.FormatInt(hashes.AHashCount+hashes.DHashCount+hashes.PHashCount))
	log.Println(log.Verbose, "IDs saved", log.FormatInt(hashes.IDCount))
	log.Println(log.Verbose, "ID groups saved", log.FormatInt(hashes.GroupCount))
	log.Println(log.Debug, "Hashes are consistent:", hashes.AHashCount == hashes.DHashCount && hashes.AHashCount == hashes.PHashCount)
	log.Println(log.Debug, "Hashes match IDs:", hashes.AHashCount == hashes.IDCount)
	log.Println(log.Verbose, "Successfully Saved V3 hashes")
	return nil
}

func downloadProcessor(chdb ch.CHDB, opts Opts, finishedDownloads <-chan download.Download, server *ch.Server) {
	defer func() {
		log.Println(log.Verbose, "Download Processor completed")
		close(server.HashingQueue)
	}()
	for dl := range finishedDownloads {
		if opts.onlyHashNewIDs && len(server.Storage.GetIDs(dl.IssueID)) > 0 {
			log.Println(log.Standard, "Skipping already hashed ID", dl.IssueID)
			continue
		}

		if chdb.PathHashed(dl.Dest) {
			log.Println(log.Standard, "Skipping already hashed ID", dl.IssueID)
			continue
		}
		var (
			file io.ReadCloser
			err  error
		)
		if dl.Image == nil {
			file, err = os.OpenFile(filepath.Join(opts.path, dl.Dest), os.O_RDWR, 0o666)
			if err != nil {
				panic(err)
			}
		} else {
			file = io.NopCloser(dl.Image)
		}
		i, format, err := image.Decode(bufio.NewReader(file))
		file.Close()
		if dl.Image != nil && dl.Image.Cap() < 10*1024*1024 {
			bufPool.Put(dl.Image)
		}
		if err != nil {
			if len(dl.Request.URL.String()) > 0 {
				log.Println(log.Standard, "Reading image failed, adding to known bad urls:", dl.Request.URL, err)
				chdb.AddURL(dl.Request.URL.String())
			} else {
				log.Println(log.Standard, "Reading image failed", dl.Dest, err)
			}
			continue // skip this image
		}
		chdb.AddPath(dl.Dest) // Add to db and remove file if opts.deleteHashedImages is true

		im := ch.Im{
			Im:      i,
			Format:  format,
			ID:      dl.IssueID,
			NewOnly: opts.onlyHashNewIDs,
		}
		server.HashingQueue <- im
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
			log.Println(log.Fatal, err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	server := ch.NewServer(context.Background(), opts.version, opts.addr, opts.onlyHashNewIDs)
	signalQueue := make(chan os.Signal, 1)
	Notify(signalQueue)
	var err error
	log.Println(log.Verbose, "Init storage")
	server.Storage, err = initializeStorage(opts)
	if err != nil {
		panic(err)
	}

	log.Println(log.Verbose, "Init 10 readers")
	rwg := sync.WaitGroup{}
	for i := range 10 {
		rwg.Go(func() { server.Reader(i) })
	}

	log.Println(log.Verbose, "Init 10 hashers")
	hwg := sync.WaitGroup{}
	for i := range 10 {
		hwg.Go(func() { server.Hasher(i) })
	}

	log.Println(log.Verbose, "Init 1 mapper")
	mwg := sync.WaitGroup{}
	mwg.Go(func() { server.Mapper(1) })

	// DecodeHashes would normally need a write lock
	// nothing else has been started yet so we don't need one
	loadedHashes := loadHashes(opts)
	server.DecodeHashes(loadedHashes)
	log.Println(log.Standard, "Loaded hashes")
	// This is loaded here so that the log doesn't hang for a few seconds before the first line
	server.HashServer = ch.NewHashServer(filepath.Join(opts.path, hashesFilename))
	loadedHashes = nil //nolint:ineffassign

	// TODO: this may cause issues if listen below fails and there are images being hashed
	server.HashLocalImages(opts.coverPath)
	_ = os.MkdirAll(opts.path, 0o755)
	chdb, err := ch.OpenCHDBBolt(opts.path, opts.deleteHashedImages)
	if err != nil {
		panic(err)
	}

	log.Println(log.Verbose, "Init downloaders")
	dwg := sync.WaitGroup{}
	dcwg := sync.WaitGroup{}
	finishedDownloadQueue := make(chan download.Download, 1)
	// startDownloadQueue := make(chan download.Download, 1)
	dcwg.Go(func() {
		downloadProcessor(chdb, opts, finishedDownloadQueue, &server)
	})

	if opts.cv.enabled {
		dwg.Go(func() {
			cvdownloader := cv.NewCVDownloader(
				opts.version,
				bufPool,
				opts.onlyHashNewIDs,
				server.Storage.GetIDs,
				chdb,
				filepath.Join(opts.path, cv.WorkDirectory),
				opts.cv.APIKey,
				opts.cv.images,
				opts.keepDownloaded,
				opts.hashDownloaded,
				finishedDownloadQueue,
			)
			// TODO:? allow a way to cancel this context. I'm not sure why
			cv.DownloadCovers(server.Context, cvdownloader)
			for {
				select {
				case <-time.After(2 * time.Hour):
					cv.DownloadCovers(server.Context, cvdownloader)
				case <-server.Context.Done():
					return
				}
			}
		})
	}

	if opts.metron.enabled {
		// TODO:? allow a way to cancel this context. I'm not sure why
		dwg.Go(func() {
			metronDownloader := metron.NewDownloader(
				opts.version,
				bufPool,
				opts.onlyHashNewIDs,
				server.Storage.GetIDs,
				chdb,
				filepath.Join(opts.path, metron.WorkDirectory),
				opts.metron.APIKey,
				opts.keepDownloaded,
				opts.hashDownloaded,
				finishedDownloadQueue,
			)
			metron.DownloadCovers(server.Context, metronDownloader)
			for {
				select {
				case <-time.After(1 * time.Hour):
					metron.DownloadCovers(server.Context, metronDownloader)
				case <-server.Context.Done():
					return
				}
			}
		})
	}
	hashEncoders := sync.WaitGroup{}
	log.Println(log.Verbose, "Init hash encoder")
	if opts.hashSaveInterval > 0 {
		hashEncoders.Go(func() {
			for {
				select {
				case <-time.After(opts.hashSaveInterval):
					err := server.HashServer.WriteHashes(server.Storage)
					if err != nil {
						log.Log(log.Fatal, "Failed to save the current hashes: %v", err)
					}
				case <-server.Context.Done():
					return
				}
			}
		})
	}

	go signalHandler(&server, signalQueue)
	if opts.memprofile != "" {
		f, err := os.Create(opts.memprofile)
		if err != nil {
			log.Println(log.Fatal, "could not create memory profile:", err)
			os.Exit(1)
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
			log.Println(log.Fatal, "could not write memory profile:", err)
		}

	}

	log.Println(log.Required, "Listening on ", server.HTTPServer.Addr)
	err = server.ListenAndServe()
	if err != nil {
		log.Println(log.Fatal, err)
	}
	log.Println(log.Required, "Shutting down comic-hasher")
	close(server.ReaderQueue)
	log.Println(log.Standard, "waiting on readers")
	rwg.Wait()
	for dw := range server.ReaderQueue {
		log.Println(log.Verbose, "Skipping read", dw)
	}

	log.Println(log.Verbose, "waiting on downloaders")
	dwg.Wait() // Downloaders send to startDownloadQueue -> finishedDownloadQueue -> server.hashingQueue

	log.Println(log.Standard, "waiting on download workers")
	// close(startDownloadQueue)
	close(finishedDownloadQueue)
	dcwg.Wait() // Wait for the download processor to finish
	for dw := range finishedDownloadQueue {
		log.Println(log.Verbose, "Skipping download", dw.IssueID)
	}

	// close(server.hashingQueue) // Closed by downloadProcessor
	log.Println(log.Standard, "waiting on hashers")
	hwg.Wait()
	for dw := range server.HashingQueue {
		log.Println(log.Verbose, "Skipping hashing", dw.ID)
	}

	close(server.MappingQueue)
	log.Println(log.Standard, "waiting on mapper")
	mwg.Wait()
	for dw := range server.MappingQueue {
		log.Println(log.Verbose, "Skipping mapping", dw.ID)
	}
	log.Println(log.Standard, "waiting on hash encoder")
	hashEncoders.Wait()
	log.Println(log.Required, "If you press Ctrl+C after this point the saved hashes will be corrupted")
	signal.Stop(signalQueue)
	close(signalQueue)
	for dw := range signalQueue {
		log.Println(log.Verbose, "Skipping", dw)
	}

	_ = chdb.Close()

	// server.EncodeHashes would normally need a read lock
	// the server has been stopped so it's not needed here
	hashes, err := server.Storage.EncodeHashes()
	if err != nil {
		log.Println(log.Fatal, "Failed to save hashes:", err)
		os.Exit(1)
	}
	if err = saveHashes(opts, hashes); err != nil {
		log.Println(log.Fatal, err)
		os.Exit(1)
	}
}
