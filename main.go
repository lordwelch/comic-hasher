package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
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

	gzip "github.com/klauspost/pgzip"

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
		storageType: Basic, version: Version,
		cv: CVOpts{
			images: cv.Images{"thumb": {}},
		},
		upstream: UpstreamOpts{
			URL: URLFlag{
				Scheme: "https",
				Host:   "comic-hasher.narnian.us",
				Path:   "/hashes",
			},
		},
	}
	showVersion, fs := registerOptions(&opts)
	err := fs.Parse(os.Args[1:])
	// Flags don't know when they are done so we call get here to cleanup some temporary data
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

	os.Exit(doStuff(opts))
}

func doStuff(opts Opts) int {
	download.Client = &http.Client{Transport: download.RT("Comic-Hasher/" + opts.version)}

	if opts.debugPort != "" {
		go func() {
			log.Println(log.Standard, http.ListenAndServe("127.0.0.1:"+opts.debugPort, nil))
		}()
	}
	if opts.coverPath != "" {
		_, err := os.Stat(opts.coverPath)
		log.Log(log.Fatal, "invalid cover path: %v: %w", opts.coverPath, err)
		return 1
	}
	if opts.cv.enabled {
		if opts.cv.APIKey == "" {
			log.Println(log.Fatal, "No ComicVine API Key provided")
			return 1
		}
	}

	opts.path, _ = filepath.Abs(opts.path)
	log.Println(log.Standard, pretty.Sprint(opts))

	err := startServer(opts)
	if err != nil {
		log.Log(log.Fatal, "comic-hasher failed: %v", err)
		return 1
	}
	return 0
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
	case Map:
		return storage.NewMapStorage()
	case Basic:
		return storage.NewBasicStorage()
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

func loadHashes(opts Opts) (*ch.SavedHashesV3, error) {
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
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			log.Println(log.Standard, "Unable to load saved hashes", err)
		}
	}
	if errors.Is(err, os.ErrNotExist) || hashReader == nil {
		log.Println(log.Standard, "No saved hashes to load")
	}

	var loadedHashes *ch.SavedHashesV3 = nil
	if opts.loadEmbeddedHashes && len(ch.Hashes) != 0 && hashReader == nil {
		log.Println(log.Standard, "Loading embedded hashes")
		loadedHashes, err = ch.LoadEmbeddedHashes(!opts.saveEmbeddedHashes && !opts.upstream.Merge)
		if err != nil {
			loadedHashes = nil
		}
	}

	if loadedHashes == nil {
		loadedHashes, err = ch.DecodeHashesV3(hashReader)
		if errors.Is(err, ch.ErrNoHashes) {
			log.Println(log.Verbose, "No saved hashes to load")
			return loadedHashes, nil
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode hashes: %w", err)
	}

	loadedHashes.LogHashInfo(log.Verbose, "")
	loadedHashes.Sort()

	if opts.upstream.DownloadHashes {
		log.Println(log.Standard, "Downloading upstream hashes from", opts.upstream.URL.String())
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		downloadedHashes, err := DownloadUpstreamHashes(ctx, download.Client, opts.upstream.URL)
		interrupted := ctx.Err() != nil
		if interrupted {
			return nil, errors.New("interrupted while downloading upstream hashes")
		}
		if err != nil {
			log.Println(log.Required, "failed to download upstream hashes")
			return loadedHashes, nil
		}
		if !opts.upstream.Merge {
			return downloadedHashes, nil
		}
		err = loadedHashes.Merge(downloadedHashes)
		if err != nil {
			return nil, fmt.Errorf("failed to merge upstream hashes: %w", err)
		}
	}

	return loadedHashes, nil
}

func DownloadUpstreamHashes(parent context.Context, client *http.Client, url URLFlag) (*ch.SavedHashesV3, error) {
	ctx, cancel := context.WithTimeout(parent, time.Second*45)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if digests := resp.Header.Get("Repr-Digest"); digests != "" {
		// MD5=:XXH3:,
		for h := range strings.SplitSeq("", ",") {
			for _, hashName := range hashNames {
				if !strings.HasPrefix(strings.ToLower(h), strings.ToLower(hashName)) {
					continue
				}
				_, h = log.Partition(h, "=:")
				h, _ = log.RPartition(h, ":")
				b64, err := base64.StdEncoding.DecodeString(h)
				if err != nil {
					return nil, err
				}
				hashers[hashName].Write(b)
				if !bytes.Equal(b64, hashers[hashName].Sum(nil)) {
					return nil, fmt.Errorf("upstream hashes did not validate")
				}
			}
		}
	}
	var reader io.Reader = bytes.NewReader(b)
	if [3]byte(b[:3]) == [3]byte{0x1F, 0x8B, 0x8} {
		gz, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("HashServer did not send a gzipped response: %w", err)
		}
		defer gz.Close()
		reader = gz
	}
	loadedHashes, err := ch.DecodeHashesV3(reader)
	if err != nil {
		return nil, err
	}
	if errors.Is(err, ch.ErrNoHashes) {
		log.Println(log.Verbose, "Upstream hashes is empty")
	}
	return loadedHashes, nil
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
	tmpPath := filepath.Join(opts.path, hashesFilename+".tmp.gz")

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("unabled to save hashes: %w", err)
	}
	defer f.Close()
	b := bufio.NewWriter(f)
	gzw := gzip.NewWriter(b)
	gzb := bufio.NewWriterSize(gzw, 32*1024)
	err = ch.EncodeHashesV3(hashes, gzb)
	if err != nil {
		return fmt.Errorf("unable to encode hashes: %w", err)
	}
	if err = gzb.Flush(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}

	if err = gzw.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}
	if err = b.Flush(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("failed to write hashes: %w", err)
	}
	if err = os.Rename(tmpPath, hashesPath); err != nil {
		return fmt.Errorf("failed to update existing file: %w", err)
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
				log.Println(log.Standard, "Failed to open downloaded file: %v: %w", dl.Dest, err)
				continue
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

func startServer(opts Opts) error {
	imaging.SetMaxProcs(2)
	if opts.cpuprofile != "" {
		f, err := os.Create(opts.cpuprofile)
		if err != nil {
			return fmt.Errorf("unable to create cpuprofile: %w", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	server := ch.NewServer(context.Background(), opts.version, opts.addr, opts.onlyHashNewIDs)
	log.EnableNonBlocking(server.Context, 30)
	signalQueue := make(chan os.Signal, 1)
	Notify(signalQueue)
	var err error
	log.Println(log.Verbose, "Init storage")
	server.Storage, err = initializeStorage(opts)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
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
	loadedHashes, err := loadHashes(opts)
	if err != nil {
		return err
	}
	server.DecodeHashes(loadedHashes)
	log.Println(log.Standard, "Loaded hashes")
	// This is loaded here so that the log doesn't hang for a few seconds before the first line
	server.HashServer = ch.NewHashServer(filepath.Join(opts.path, hashesFilename), opts.useAllChecksums)
	loadedHashes = nil //nolint:ineffassign

	_ = os.MkdirAll(opts.path, 0o755)
	chdb, err := ch.OpenCHDBBolt(opts.path, opts.deleteHashedImages)
	if err != nil {
		return fmt.Errorf("failed to initialize CHDB: %w", err)
	}

	log.Println(log.Verbose, "Init downloaders")
	dwg := sync.WaitGroup{}
	dcwg := sync.WaitGroup{}
	finishedDownloadQueue := make(chan download.Download, 1)
	// startDownloadQueue := make(chan download.Download, 1)
	dcwg.Go(func() {
		downloadProcessor(chdb, opts, finishedDownloadQueue, server)
	})
	dcwg.Go(func() {
		server.HashLocalImages(opts.coverPath)
	})
	var cvErr error
	server.CVDownloader, cvErr = cv.NewCVDownloader(
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
	if opts.cv.enabled {
		dwg.Go(func() {
			if cvErr != nil {
				log.Println(log.Required, "Failed to start ComicVine Downloader: %v", cvErr)
				return
			}
			defer server.CVDownloader.Close()
			cv.DownloadCovers(server.Context, server.CVDownloader.(*cv.Downloader))
			for {
				select {
				case <-time.After(2 * time.Hour):
					cv.DownloadCovers(server.Context, server.CVDownloader.(*cv.Downloader))
				case <-server.Context.Done():
					return
				}
			}
		})
	}

	var metronErr error
	server.MetronDownloader, metronErr = metron.NewDownloader(
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
	if opts.metron.enabled {
		dwg.Go(func() {
			if metronErr != nil {
				log.Println(log.Required, "Failed to start Metron Downloader: %v", metronErr)
				return
			}
			defer server.MetronDownloader.Close()
			metron.DownloadCovers(server.Context, server.MetronDownloader.(*metron.Downloader))
			for {
				select {
				case <-time.After(1 * time.Hour):
					metron.DownloadCovers(server.Context, server.MetronDownloader.(*metron.Downloader))
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

	go signalHandler(server, signalQueue)
	if opts.memprofile != "" {
		f, err := os.Create(opts.memprofile)
		if err != nil {
			log.Println(log.Fatal, "could not create memory profile:", err)
			time.Sleep(11 * time.Millisecond) // for logging to complete
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

	log.Println(log.Verbose, "waiting on downloaders")
	dwg.Wait() // Downloaders send to finishedDownloadQueue -> server.hashingQueue

	log.Println(log.Standard, "waiting on download workers")
	// Downloaders are done which means that we can close finishedDownloadQueue
	close(finishedDownloadQueue)
	dcwg.Wait() // Wait for all hashing queue producers to finish.
	close(server.HashingQueue)
	// This should never happen but we drain anyway
	for dw := range finishedDownloadQueue {
		log.Println(log.Verbose, "Skipping download", dw.IssueID)
	}

	log.Println(log.Standard, "waiting on hashers")
	hwg.Wait()
	for dw := range server.HashingQueue { // Closed by downloadProcessor. This should never happen as hwg.Wait() should only return after all hashing is complete
		log.Println(log.Verbose, "Skipping hashing", dw.ID)
	}

	close(server.MappingQueue)
	log.Println(log.Standard, "waiting on mappers")
	mwg.Wait()
	// This should never happen but we drain anyway
	for dw := range server.MappingQueue {
		log.Println(log.Verbose, "Skipping mapping", dw.ID)
	}
	log.Println(log.Standard, "waiting on hash encoder server")
	// Go doesn't really have a way to cancel IO operations so we have to wait for this no matter what
	hashEncoders.Wait()
	log.Println(log.Required, "If you press Ctrl+C after this point the saved hashes will be corrupted")
	signal.Stop(signalQueue)
	close(signalQueue)
	for dw := range signalQueue {
		log.Println(log.Verbose, "Skipping", dw)
	}

	log.Println(log.Verbose, "Compacting CHDB")
	err = chdb.Compact()
	if err != nil {
		log.Println(log.Verbose, "Failed to compact the CHDB, this is probably fine:", err)
	}
	_ = chdb.Close()

	// server.EncodeHashes would normally need a read lock
	// the server has been stopped so it's not needed here
	hashes, err := server.Storage.EncodeHashes()
	if err != nil {
		return fmt.Errorf("failed to save hashes: %w", err)
	}
	return saveHashes(opts, hashes)
}
