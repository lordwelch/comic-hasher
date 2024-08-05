package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io/fs"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

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
	Partial_ahash [8]map[uint8][]uint64 // Maps partial hashes to their potential full hashes
	Partial_dhash [8]map[uint8][]uint64 // Maps partial hashes to their potential full hashes
	Partial_phash [8]map[uint8][]uint64 // Maps partial hashes to their potential full hashes
	Full_ahash    map[uint64]ch.IDList  // Maps ahash's to lists of ID's
	Full_dhash    map[uint64]ch.IDList  // Maps dhash's to lists of ID's
	Full_phash    map[uint64]ch.IDList  // Maps phash's to lists of ID's
	// IDToCover     map[string]string // IDToCover is a map of domain:ID to an index to covers eg IDToCover['comicvine.gamespot.com:12345'] = 0
	// covers       []ch.Cover
	readerQueue  chan string
	hashingQueue chan ch.Im
	mappingQueue chan ch.Hash
	// hashes are a uint64 split into 8 pieces or a unint64 for quick lookup, the value is an index to covers
}

// var key = []byte(uuid.New().String())[:16]
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// mustDropPrivileges()
	cover_path := flag.String("cover_path", "", "path to covers to add to hash database")
	flag.Parse()
	if *cover_path == "" {
		log.Fatal("You must supply a path")
	}
	st, err := os.Stat(*cover_path)
	if err != nil {
		panic(err)
	}
	fmt.Println(st)
	startServer(*cover_path)
}

func (s *Server) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	return strings.TrimSpace("lordwelch"), true
}

// func (s *Server) setupOauthHandlers() error {
// 	redirectURI := *s.BaseURL
// 	redirectURI.Path = "/oauth/callback"
// 	successURI := *s.BaseURL
// 	successURI.Path = "/success"
// 	failURI := *s.BaseURL
// 	failURI.RawQuery = url.Values{"auth": []string{"fail"}}.Encode()

// 	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

// 	options := []rp.Option{
// 		rp.WithCookieHandler(cookieHandler),
// 		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
// 	}

// 	provider, err := rp.NewRelyingPartyOIDC(os.Getenv("COMICHASHER_PROVIDER_URL"), os.Getenv("COMICHASHER_CLIENT_ID"), os.Getenv("COMICHASHER_CLIENT_SECRET"), redirectURI.String(), strings.Split(os.Getenv("COMICHASHER_SCOPES"), ","), options...)
// 	if err != nil {
// 		return fmt.Errorf("error creating provider: %w", err)
// 	}

// 	// generate some state (representing the state of the user in your application,
// 	// e.g. the page where he was before sending him to login
// 	state := func() string {
// 		return uuid.New().String()
// 	}

// 	// register the AuthURLHandler at your preferred path
// 	// the AuthURLHandler creates the auth request and redirects the user to the auth server
// 	// including state handling with secure cookie and the possibility to use PKCE
// 	s.mux.Handle("/login", rp.AuthURLHandler(state, provider))

// 	// for demonstration purposes the returned userinfo response is written as JSON object onto response
// 	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
// 		s.token <- tokens
// 		w.Header().Add("location", successURI.String())
// 		w.WriteHeader(301)
// 	}

// 	// register the CodeExchangeHandler at the callbackPath
// 	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
// 	// with the returned tokens from the token endpoint
// 	s.mux.Handle(redirectURI.Path, rp.CodeExchangeHandler(marshalUserinfo, provider))
// 	return nil
// }

func (s *Server) setupAppHandlers() {
	s.mux.HandleFunc("/add_cover", s.add_cover)
	s.mux.HandleFunc("/get_cover", s.get_cover)
	s.mux.HandleFunc("/match_cover_hash", s.match_cover_hash)
}

func (s *Server) get_cover(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	var (
		values url.Values = r.URL.Query()
		domain            = strings.TrimSpace(values.Get("domain"))
		ID                = strings.TrimSpace(values.Get("id"))
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

func (s *Server) getMatches(ahash, dhash, phash uint64) []ch.Result {

	var foundMatches []ch.Result

	if matchedResults, ok := s.Full_ahash[ahash]; ok {
		foundMatches = append(foundMatches, ch.Result{matchedResults, 0, ch.ImageHash{ahash, goimagehash.AHash}})
	}
	if matchedResults, ok := s.Full_dhash[dhash]; ok {
		foundMatches = append(foundMatches, ch.Result{matchedResults, 0, ch.ImageHash{ahash, goimagehash.DHash}})
	}
	if matchedResults, ok := s.Full_phash[phash]; ok {
		foundMatches = append(foundMatches, ch.Result{matchedResults, 0, ch.ImageHash{ahash, goimagehash.PHash}})
	}

	// If we have exact matches don't bother with other matches
	if len(foundMatches) > 0 {
		return foundMatches
	}

	for i, partial_hash := range ch.SplitHash(ahash) {
		for _, match := range ch.Atleast(8, ahash, s.Partial_ahash[i][partial_hash]) {
			if matchedResults, ok := s.Full_ahash[match.Hash]; ok {
				foundMatches = append(foundMatches, ch.Result{matchedResults, match.Distance, ch.ImageHash{match.Hash, goimagehash.AHash}})
			}
		}
	}

	for i, partial_hash := range ch.SplitHash(dhash) {
		for _, match := range ch.Atleast(8, dhash, s.Partial_dhash[i][partial_hash]) {
			if matchedResults, ok := s.Full_dhash[match.Hash]; ok {
				foundMatches = append(foundMatches, ch.Result{matchedResults, match.Distance, ch.ImageHash{match.Hash, goimagehash.DHash}})
			}
		}
	}

	for i, partial_hash := range ch.SplitHash(phash) {
		for _, match := range ch.Atleast(8, phash, s.Partial_phash[i][partial_hash]) {
			if matchedResults, ok := s.Full_phash[match.Hash]; ok {
				foundMatches = append(foundMatches, ch.Result{matchedResults, match.Distance, ch.ImageHash{match.Hash, goimagehash.PHash}})
			}
		}
	}

	return foundMatches
}

func (s *Server) match_cover_hash(w http.ResponseWriter, r *http.Request) {
	user, authed := s.authenticated(w, r)
	if !authed || user == "" {
		http.Error(w, "Invalid Auth", http.StatusForbidden)
		return
	}
	var (
		values   = r.URL.Query()
		ahashStr = strings.TrimSpace(values.Get("ahash"))
		dhashStr = strings.TrimSpace(values.Get("dhash"))
		phashStr = strings.TrimSpace(values.Get("phash"))
		ahash    uint64
		dhash    uint64
		phash    uint64
		err      error
	)
	if ahash, err = strconv.ParseUint(ahashStr, 16, 64); err != nil && ahashStr != "" {
		log.Printf("could not parse ahash: %s", ahashStr)
		http.Error(w, "parse fail", http.StatusBadRequest)
		return
	}
	if dhash, err = strconv.ParseUint(dhashStr, 16, 64); err != nil && dhashStr != "" {
		log.Printf("could not parse dhash: %s", dhashStr)
		http.Error(w, "parse fail", http.StatusBadRequest)
		return
	}
	if phash, err = strconv.ParseUint(phashStr, 16, 64); err != nil && phashStr != "" {
		log.Printf("could not parse phash: %s", phashStr)
		http.Error(w, "parse fail", http.StatusBadRequest)
		return
	}
	matches := s.getMatches(ahash, dhash, phash)
	if len(matches) > 0 {
		covers, err := json.Marshal(matches)
		log.Println(err)
		w.Header().Add("Content-Type", "application/json")
		w.Write(covers)
		w.Write([]byte{'\n'})
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintln(w, "{\"msg\":\"No hashes found\"}")
}

func (s *Server) add_cover(w http.ResponseWriter, r *http.Request) {
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
	i, format, err := image.Decode(r.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	log.Printf("Decoded %s image from %s", format, user)
	s.hashingQueue <- ch.Im{Im: i, Format: format, Domain: ch.Source(domain), ID: ID, Path: ""}
	fmt.Fprintln(w, "Success")
}

func (s *Server) mapHashes(hash ch.Hash) {
	_, ahash_ok := s.Full_ahash[hash.Ahash.GetHash()]
	if !ahash_ok {
		s.Full_ahash[hash.Ahash.GetHash()] = make(ch.IDList)
	}
	s.Full_ahash[hash.Ahash.GetHash()][hash.Domain] = ch.Insert(s.Full_ahash[hash.Ahash.GetHash()][hash.Domain], hash.ID)
	_, dhash_ok := s.Full_dhash[hash.Dhash.GetHash()]
	if !dhash_ok {
		s.Full_dhash[hash.Dhash.GetHash()] = make(ch.IDList)
	}
	s.Full_dhash[hash.Dhash.GetHash()][hash.Domain] = ch.Insert(s.Full_dhash[hash.Dhash.GetHash()][hash.Domain], hash.ID)
	_, phash_ok := s.Full_phash[hash.Phash.GetHash()]
	if !phash_ok {
		s.Full_phash[hash.Phash.GetHash()] = make(ch.IDList)
	}
	s.Full_phash[hash.Phash.GetHash()][hash.Domain] = ch.Insert(s.Full_phash[hash.Phash.GetHash()][hash.Domain], hash.ID)

	for i, partial_hash := range ch.SplitHash(hash.Ahash.GetHash()) {
		s.Partial_ahash[i][partial_hash] = ch.Insert(s.Partial_ahash[i][partial_hash], hash.Ahash.GetHash())
	}
	for i, partial_hash := range ch.SplitHash(hash.Dhash.GetHash()) {
		s.Partial_dhash[i][partial_hash] = ch.Insert(s.Partial_dhash[i][partial_hash], hash.Dhash.GetHash())
	}
	for i, partial_hash := range ch.SplitHash(hash.Phash.GetHash()) {
		s.Partial_phash[i][partial_hash] = ch.Insert(s.Partial_phash[i][partial_hash], hash.Phash.GetHash())
	}
}

func (s *Server) initHashes() {
	for i := range s.Partial_ahash {
		s.Partial_ahash[i] = make(map[uint8][]uint64)
	}
	for i := range s.Partial_dhash {
		s.Partial_dhash[i] = make(map[uint8][]uint64)
	}
	for i := range s.Partial_phash {
		s.Partial_phash[i] = make(map[uint8][]uint64)
	}
	s.Full_ahash = make(map[uint64]ch.IDList)
	s.Full_dhash = make(map[uint64]ch.IDList)
	s.Full_phash = make(map[uint64]ch.IDList)
	// s.IDToCover = make(map[string]string)
}

func (s *Server) mapper() {
	var total uint64 = 0
	for {
		select {
		case hash := <-s.mappingQueue:
			if total%1000 == 0 {
				mem := ch.MemStats()
				if mem > 10*1024*1024*1024 {
					fmt.Println("Forcing gc", mem, "G")
					runtime.GC()
				}
			}
			total++

			s.mapHashes(hash)
		}
	}
}

func (s *Server) hasher(workerID int) {
	for {
		select {
		case i := <-s.hashingQueue:
			start := time.Now()

			hash := ch.HashImage(i)
			if hash.Domain == "" {
				continue
			}

			s.mappingQueue <- hash

			elapsed := time.Now().Sub(start)
			// fmt.Printf("%#064b\n", ahash.GetHash())
			// fmt.Printf("%#064b\n", dhash.GetHash())
			// fmt.Printf("%#064b\n", phash.GetHash())
			log.Printf("Hashing took %v: worker: %v. path: %s ahash: %064b id: %s\n", elapsed, workerID, i.Path, hash.Ahash.GetHash(), hash.ID)
		}
	}
}

func (s *Server) reader(workerID int) {
	for {
		select {
		case path := <-s.readerQueue:
			file, err := os.Open(path)
			if err != nil {
				panic(err)
			}
			i, format, err := image.Decode(bufio.NewReader(file))
			if err != nil {
				continue // skip this image
			}
			file.Close()
			// fmt.Println("Hashing", path)
			im := ch.Im{Im: i, Format: format, Domain: "comicvine.gamespot.com", ID: filepath.Base(filepath.Dir(path)), Path: path}
			s.hashingQueue <- im
		}
	}
}

//	func (s *Server) CoverByID(ID string) uint32 {
//		v,ok :=s.IDToCover[ID]
//		return 0
//	}
func (s *Server) FindHashes() {
}

func startServer(cover_path string) {
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	mux := http.NewServeMux()
	server := Server{
		// token:        make(chan *oidc.Tokens),
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
	imaging.SetMaxProcs(1)
	fmt.Println("init hashes")
	server.initHashes()
	// server.setupOauthHandlers()
	fmt.Println("init handlers")
	server.setupAppHandlers()
	fmt.Println("init hashers")
	go server.reader(1)
	go server.reader(2)
	go server.reader(3)
	go server.reader(4)
	go server.reader(5)
	go server.reader(6)
	go server.reader(7)
	go server.reader(8)
	go server.reader(9)
	go server.reader(10)

	go server.hasher(1)
	go server.hasher(2)
	go server.hasher(3)
	go server.hasher(4)
	go server.hasher(5)
	go server.hasher(6)
	go server.hasher(7)
	go server.hasher(8)
	go server.hasher(9)
	go server.hasher(10)

	fmt.Println("init mapper")
	go server.mapper()

	fmt.Println("Starting local hashing go routine")
	go func() {
		fmt.Println("Hashing covers at ", cover_path)
		start := time.Now()
		err := filepath.WalkDir(cover_path, func(path string, d fs.DirEntry, err error) error {
			select {
			case s := <-sig:
				server.httpServer.Shutdown(context.TODO())
				return fmt.Errorf("Signal: %v", s)
			default:
			}
			if d.IsDir() { // Only hash thumbnails for now
				return nil
			}
			fmt.Println(len(server.readerQueue))
			server.readerQueue <- path
			return nil
		})
		elapsed := time.Now().Sub(start)
		fmt.Println("Err:", err, "local hashing took", elapsed)

		select {
		case s := <-sig:
			server.httpServer.Shutdown(context.TODO())
			log.Printf("Signal: %v", s)
		}
	}()

	fmt.Println("Listening on ", server.httpServer.Addr)
	err := server.httpServer.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
	f, er := os.Create("memprofile")
	if er != nil {
		fmt.Println("Error in creating file for writing memory profile to: ", er)
		return
	}
	defer f.Close()
	runtime.GC()
	if e := pprof.WriteHeapProfile(f); e != nil {
		fmt.Println("Error in writing memory profile: ", e)
		return
	}
}
