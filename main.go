package main

import (
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"

	"github.com/corona10/goimagehash"
	"github.com/google/uuid"

	"github.com/disintegration/imaging"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

const (
	h_1 uint64 = 0b11111111 << (8 * iota)
	h_2
	h_3
	h_4
	h_5
	h_6
	h_7
	h_8
)

const (
	shift_1 = (8 * iota)
	shift_2
	shift_3
	shift_4
	shift_5
	shift_6
	shift_7
	shift_8
)

type Cover map[string][]string // IDs is a map of domain to ID eg IDs['comicvine.gamespot.com'] = []string{"1235"}

// type Cover struct {
// 	AHash uint64
// 	DHash uint64
// 	PHash uint64
// 	IDs   map[string][]string // IDs is a map of domain to ID eg IDs['comicvine.gamespot.com'] = []string{"1235"}
// }

type Server struct {
	httpServer *http.Server
	mux        *http.ServeMux
	BaseURL    *url.URL
	token      chan<- *oidc.Tokens
	ahash      [8]map[uint8]uint32
	dhash      [8]map[uint8]uint32
	phash      [8]map[uint8]uint32
	fAhash     map[uint64]uint32
	fDhash     map[uint64]uint32
	fPhash     map[uint64]uint32
	IDToCover  map[string]uint32 // IDToCover is a map of domain:id to an index to covers eg IDToCover['comicvine.gamespot.com:12345'] = 0
	covers     []Cover
	// hashes are a uint64 split into 8 pieces or a unint64 for quick lookup, the value is an index to covers
}

var key = []byte(uuid.New().String())[:16]

func main() {
	// mustDropPrivileges()
	startServer()
}

func (s *Server) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	return strings.TrimSpace("lordwelch"), true
}

func (s *Server) setupOauthHandlers() error {
	redirectURI := *s.BaseURL
	redirectURI.Path = "/oauth/callback"
	successURI := *s.BaseURL
	successURI.Path = "/success"
	failURI := *s.BaseURL
	failURI.RawQuery = url.Values{"auth": []string{"fail"}}.Encode()

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	provider, err := rp.NewRelyingPartyOIDC(os.Getenv("COMICHASHER_PROVIDER_URL"), os.Getenv("COMICHASHER_CLIENT_ID"), os.Getenv("COMICHASHER_CLIENT_SECRET"), redirectURI.String(), strings.Split(os.Getenv("COMICHASHER_SCOPES"), ","), options...)
	if err != nil {
		return fmt.Errorf("error creating provider: %w", err)
	}

	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	// register the AuthURLHandler at your preferred path
	// the AuthURLHandler creates the auth request and redirects the user to the auth server
	// including state handling with secure cookie and the possibility to use PKCE
	s.mux.Handle("/login", rp.AuthURLHandler(state, provider))

	// for demonstration purposes the returned userinfo response is written as JSON object onto response
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
		s.token <- tokens
		w.Header().Add("location", successURI.String())
		w.WriteHeader(301)
	}

	// register the CodeExchangeHandler at the callbackPath
	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	// with the returned tokens from the token endpoint
	s.mux.Handle(redirectURI.Path, rp.CodeExchangeHandler(marshalUserinfo, provider))
	return nil
}

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
		values = r.URL.Query()
		domain = strings.TrimSpace(values.Get("domain"))
		id     = strings.TrimSpace(values.Get("id"))
	)
	if id == "" {
		log.Println("No ID Provided")
		http.Error(w, "No ID Provided", http.StatusBadRequest)
		return
	}
	if domain == "" {
		log.Println("No domain Provided")
		http.Error(w, "No domain Provided", http.StatusBadRequest)
		return
	}
	if index, ok := s.IDToCover[domain+":"+id]; ok {
		covers, err := json.Marshal(s.covers[index])
		if err == nil {
			w.Header().Add("Content-Type", "application/json")
			w.Write(covers)
			return
		}
	}
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
	if index, ok := s.fAhash[ahash]; ok {
		covers, err := json.Marshal(s.covers[index])
		if err == nil {
			w.Header().Add("Content-Type", "application/json")
			w.Write(covers)
			return
		}
	}
	if index, ok := s.fDhash[dhash]; ok {
		covers, err := json.Marshal(s.covers[index])
		if err == nil {
			w.Header().Add("Content-Type", "application/json")
			w.Write(covers)
			return
		}
	}
	if index, ok := s.fPhash[phash]; ok {
		covers, err := json.Marshal(s.covers[index])
		if err == nil {
			w.Header().Add("Content-Type", "application/json")
			w.Write(covers)
			return
		}
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
		id     = strings.TrimSpace(values.Get("id"))
	)
	if id == "" {
		log.Println("No ID Provided")
		http.Error(w, "No ID Provided", http.StatusBadRequest)
		return
	}
	if domain == "" {
		log.Println("No domain Provided")
		http.Error(w, "No domain Provided", http.StatusBadRequest)
		return
	}
	im, format, err := image.Decode(r.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	log.Printf("Decoded %s image from %s", format, user)
	im = &goimagehash.YCbCr{YCbCr: im.(*image.YCbCr)}
	i := imaging.Resize(im, 9, 8, imaging.Linear)
	bmp.Encode(w, i)
	fmt.Println(im.Bounds())

	var (
		ahash *goimagehash.ImageHash
		dhash *goimagehash.ImageHash
		phash *goimagehash.ImageHash
	)

	ahash, err = goimagehash.AverageHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to ahash Image: %s", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	dhash, err = goimagehash.DifferenceHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to dhash Image: %s", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	phash, err = goimagehash.PerceptionHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to phash Image: %s", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	fmt.Printf("%#064b\n", ahash.GetHash())
	fmt.Printf("%#064b\n", dhash.GetHash())
	fmt.Printf("%#064b\n", phash.GetHash())

	s.covers = append(s.covers, make(Cover))

	s.covers[len(s.covers)-1][domain] = append(s.covers[len(s.covers)-1][domain], id)

	s.IDToCover[domain+":"+id] = uint32(len(s.covers) - 1)

	s.mapHashes(uint32(len(s.covers)-1), ahash, dhash, phash)
}

func (s *Server) mapHashes(index uint32, ahash, dhash, phash *goimagehash.ImageHash) {
	s.fAhash[ahash.GetHash()] = index
	s.fDhash[dhash.GetHash()] = index
	s.fPhash[phash.GetHash()] = index
	for i, partial_hash := range SplitHash(ahash.GetHash()) {
		s.ahash[i][partial_hash] = index
	}
	for i, partial_hash := range SplitHash(dhash.GetHash()) {
		s.dhash[i][partial_hash] = index
	}
	for i, partial_hash := range SplitHash(phash.GetHash()) {
		s.phash[i][partial_hash] = index
	}
}

func (s *Server) initHashes() {
	for i := range s.ahash {
		s.ahash[i] = make(map[uint8]uint32)
	}
	for i := range s.dhash {
		s.dhash[i] = make(map[uint8]uint32)
	}
	for i := range s.phash {
		s.phash[i] = make(map[uint8]uint32)
	}
	s.fAhash = make(map[uint64]uint32)
	s.fDhash = make(map[uint64]uint32)
	s.fPhash = make(map[uint64]uint32)
	s.IDToCover = make(map[string]uint32)
}

func SplitHash(hash uint64) [8]uint8 {
	return [8]uint8{
		uint8((hash & h_8) >> shift_8),
		uint8((hash & h_7) >> shift_7),
		uint8((hash & h_6) >> shift_6),
		uint8((hash & h_5) >> shift_5),
		uint8((hash & h_4) >> shift_4),
		uint8((hash & h_3) >> shift_3),
		uint8((hash & h_2) >> shift_2),
		uint8((hash & h_1) >> shift_1),
	}
}

//	func (s *Server) CoverByID(id string) uint32 {
//		v,ok :=s.IDToCover[id]
//		return 0
//	}
func (s *Server) FindHashes() {
}

func startServer() {
	mux := http.NewServeMux()
	server := Server{
		token: make(chan *oidc.Tokens),
		mux:   mux,
		httpServer: &http.Server{
			Addr:           ":8080",
			Handler:        mux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
	}
	server.initHashes()
	// server.setupOauthHandlers()
	server.setupAppHandlers()
	err := server.httpServer.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
