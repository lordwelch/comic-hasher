package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/comic-hasher/cv"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

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
	_, _ = fmt.Fprintf(f.Output(), "Usage of %s:\n", f.Name())
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
		if _, err := strconv.ParseBool(fmt.Sprintf("%v", currentFlag.Value)); err == nil && !slices.ContainsFunc([]string{"v", "version", "help", "h"},
			func(v string) bool {
				return string(ch.Lower(currentFlag.Name)) == v
			},
		) {
			fmt.Fprintf(&b, " true|false")
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
			_, _ = fmt.Fprintf(f.Output(), "\n%s:\n", toTitle.String(group))
		}
		for _, item := range helpItems[group] {
			_, _ = fmt.Fprintln(f.Output(), item)
		}
	}
	// If calling String on any zero flag.Values triggered a panic, print
	// the messages after the full set of defaults so that the programmer
	// knows to fix the panic.
	if errs := isZeroValueErrs; len(errs) > 0 {
		_, _ = fmt.Fprintln(f.Output())
		for _, err := range errs {
			_, _ = fmt.Fprintln(f.Output(), err)
		}
	}
}

func registerOptions(opts *Opts) (*bool, *flag.FlagSet) {
	wd := "comic-hasher"
	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)
	fs.Usage = func() { Usage(fs) }
	fs.StringVar(&opts.addr, "listen", ":8080", "Address to listen on")
	fs.StringVar(&opts.path, "path", "./"+wd, "Path for comic-hasher to store files")
	fs.StringVar(&opts.coverPath, "cover-path", "", "`Path` to local covers to add to hash database.\nMust be in the form '{cover-path}/{domain}/{id}/*'\neg for --cover-path /covers it should look like /covers/comicvine.gamespot.com/10000/image.gif")

	fs.BoolVar(&opts.loadEmbeddedHashes, "load-embedded-hashes", true, "Use hashes embedded in the application if there are no saved hashes to load")
	fs.BoolVar(&opts.saveEmbeddedHashes, "save-embedded-hashes", true, "Allows blocking the saving of the embedded hashes")
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
	fs.BoolVar(showVersion, "V", false, "")

	fmt.Println(showVersion)

	return showVersion, fs
}

var (
	groupOrder = []string{"", "file", "hash", "download", "comic vine", "debug"}
	groups     = map[string]string{
		"load-embedded-hashes": "file",
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
