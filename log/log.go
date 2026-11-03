package log

import (
	"context"
	"fmt"
	stdlog "log"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

type Level int

func (l Level) String() string {
	if str, ok := Levels[l]; ok {
		return str
	}
	return strconv.Itoa(int(l))
}

func (l Level) GoString() string {
	return l.String()
}

func FormatInt[T uint32 | int | int64](n T) string {
	in := strconv.FormatInt(int64(n), 10)
	numOfDigits := len(in)
	if n < 0 {
		numOfDigits-- // First character is the - sign (not a digit)
	}
	numOfCommas := (numOfDigits - 1) / 3

	out := make([]byte, len(in)+numOfCommas)
	if n < 0 {
		in, out[0] = in[1:], '-'
	}

	for i, j, k := len(in)-1, len(out)-1, 0; ; i, j = i-1, j-1 {
		out[j] = in[i]
		if i == 0 {
			return string(out)
		}
		if k++; k == 3 {
			j, k = j-1, 0
			out[j] = ','
		}
	}
}

// LogLevels needs Logger to be lowercase. Use SetLevel instead of assigning to this directly
var LogLevels = map[Logger]Level{}

func SetLevel(logger Logger, level Level) {
	if logger == ALL {
		for logger := range LogLevels {
			LogLevels[logger] = level
		}
		return
	}
	logger = Logger(strings.ToLower(string(logger)))
	loggers, isAlias := LoggerAliases[logger]
	if isAlias {
		for _, logger := range loggers {
			LogLevels[logger] = level
		}
		return
	}
	LogLevels[logger] = level
	LogLevels[Logger(strings.ToLower(string(logger)))] = level
}

var LoggerAliases = map[Logger][]Logger{}

func Aliases() []string {
	aliases := make([]string, 0, len(LoggerAliases))
	for alias := range LoggerAliases {
		aliases = append(aliases, string(alias))
	}
	return aliases
}

func AvailableLoggers() []string {
	_loggers := make([]string, len(LogLevels))
	_loggers[0] = string(defaultLogger)
	loggers := _loggers[1:1]
	for logger := range LogLevels {
		if logger == defaultLogger {
			continue
		}
		loggers = append(loggers, string(logger))
	}
	slices.Sort(loggers)
	return _loggers
}

func AvailableLevels() []string {
	_levels := make([]Level, 0, len(Levels))
	for level := range Levels {
		_levels = append(_levels, level)
	}
	slices.Sort(_levels)
	_strLevels := make([]string, 0, len(_levels))
	for _, level := range _levels {
		_strLevels = append(_strLevels, level.String())
	}
	return _strLevels
}

// Logger Use NewLogger
type Logger string

const (
	Trace       Level = -5   // Trace
	Debug       Level = -3   // Debug
	MoreVerbose Level = -2   // More Verbose
	Verbose     Level = -1   // Verbose
	Standard    Level = 0    // Standard
	Required    Level = 1    // Required
	Fatal       Level = 9999 // Fatal
)

type (
	// Record [4]any
	Record struct {
		logger Logger
		level  Level
		pcs    []uintptr
		msg    string
		args   []any
	}
)

type Flag map[Logger]Level

func (f Flag) String() string {
	var str strings.Builder
	for key, value := range f {
		str.WriteString(string(key))
		str.WriteRune(':')
		str.WriteString(value.String())
		str.WriteString(",")
	}
	return strings.TrimRight(str.String(), ",")
}

func (f *Flag) Get() any {
	delete(*f, "started")
	return *f
}

func (f *Flag) Set(s string) error {
	if (*f) == nil {
		*f = Flag{"started": 0}
	} else if _, started := (*f)["started"]; !started {
		*f = Flag{"started": 0} // clear the map if this is the first time it's called
	}
	for item := range strings.SplitSeq(strings.ToLower(s), ",") {
		logName, levelName := Partition(item, ":")
		if logName == "" {
			logName = "ALL"
		}
		if levelName == "" {
			levelName = logName
			logName = "ALL"
		}
		logger := Logger(logName)
		_, isLogger := LogLevels[logger]
		_, isAlias := LoggerAliases[logger]
		if !(isLogger || isAlias || logger == "ALL") {
			return fmt.Errorf("unknown log name: %v", logName)
		}
		var validLevel bool
		(*f)[logger], validLevel = GetLevel(levelName)
		if !validLevel {
			return fmt.Errorf("unknown log level: %v", levelName)
		}
		SetLevel(logger, (*f)[logger])
	}
	return nil
}

var LevelNames = map[string]Level{
	"trace":       Trace,
	"debug":       Debug,
	"moreverbose": MoreVerbose,
	"verbose":     Verbose,
	"standard":    Standard,
	"required":    Required,
	"fatal":       Fatal,
}

var Levels = map[Level]string{
	Trace:       "Trace",
	Debug:       "Debug",
	MoreVerbose: "MoreVerbose",
	Verbose:     "Verbose",
	Standard:    "Standard",
	Required:    "Required",
	Fatal:       "Fatal",
}

var tokens = []string{ // TODO: Add a log format option??
	"{level}",
	"{message}",
	"{file}",
	"{longfile}",
	"{line}",
	"{function}",
	"{logger}",
}

var funcNames = map[string]bool{
	"Callers":      false, // we exclude the runtime module so shouldn't be necessary. Technically true for all other functions listed here as well
	"Fatal":        true,
	"Fatalf":       true,
	"Fatalln":      true,
	"Flags":        true,
	"Panic":        true,
	"Panicf":       true,
	"Panicln":      true,
	"Prefix":       true,
	"Print":        true,
	"Printf":       true,
	"Println":      true,
	"Debug":        true,
	"DebugContext": true,
	"Error":        true,
	"ErrorContext": true,
	"Info":         true,
	"InfoContext":  true,
	"Log":          true,
	"LogAttrs":     true,
	"Warn":         true,
	"WarnContext":  true,
}

var modNames = map[string]bool{
	"log":     true,
	"slog":    true,
	"slogr":   true,
	"logr":    true,
	"zap":     true,
	"runtime": true,
	"zerolog": true,
}

var LogFormat = "{file}:{line}: {message}"

func FromContext(ctx context.Context) Logger {
	logger, ok := ctx.Value(Logger("context")).(Logger)
	if ok {
		return logger
	}
	return defaultLogger
}

func NewContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, Logger("context"), logger)
}

func GetLevel(str string) (Level, bool) {
	level, ok := LevelNames[strings.ToLower(str)]
	if ok {
		return level, true
	}
	num, err := strconv.Atoi(str)
	if err == nil {
		return Level(num), true
	}
	return Standard, false
}

func format(fmtString string, r Record) string {
	workStr := fmtString
	i := make([]any, 0, 5)
	function, file, line := "", "", -1
	start := strings.Index(workStr, "{")
	for start >= 0 && start < len(workStr) {
		workStr = workStr[start:]
		end := strings.Index(workStr, "}")
		if end < 0 {
			break
		}
		switch key := workStr[:end+1]; key {
		case "{level}":
			i = append(i, r.level)
		case "{message}":
			msg := ""
			if r.msg == "" {
				msg = fmt.Sprintln(r.args...)
				msg = msg[:len(msg)-1]
			} else {
				msg = fmt.Sprintf(r.msg, r.args...)
			}
			i = append(i, msg)
		case "{file}":
			if line == -1 {
				function, file, line = GetRealFunc(r.pcs)
			}

			i = append(i, path.Base(file))
		case "{longfile}":
			if line == -1 {
				function, file, line = GetRealFunc(r.pcs)
			}
			i = append(i, file)
		case "{line}":
			if line == -1 {
				function, file, line = GetRealFunc(r.pcs)
			}
			i = append(i, line)
		case "{function}":
			if line == -1 {
				function, file, line = GetRealFunc(r.pcs)
			}
			i = append(i, function)
		case "{logger}":
			i = append(i, r.logger)
		}
		workStr = workStr[1:]
		start = strings.Index(workStr, "{")
	}

	sprintString := strings.NewReplacer(
		"{level}", "%v",
		"{message}", "%v",
		"{file}", "%v",
		"{longfile}", "%v",
		"{line}", "%v",
		"{function}", "%v",
		"{logger}", "%v",
	).Replace(fmtString)
	return fmt.Sprintf(sprintString, i...)
}

// Partition splits the string at the first occurrence of sep, and return the part before the separator and the part after the separator. If the separator is not found, return the string itself, followed an empty string.
// (The same as python's str.partition)
func Partition(s string, sep string) (string, string) {
	index := strings.Index(s, sep)
	if index < 0 {
		return s, ""
	}
	return s[0:index], s[index+1:]
}

// RPartition splits the string at the last occurrence of sep, and return the part before the separator and the part after the separator. If the separator is not found, return an empty string, followed by the string itself.
// (The same as python's str.rpartition)
func RPartition(s string, sep string) (string, string) {
	index := strings.LastIndex(s, sep)
	if index < 0 {
		return "", s
	}
	return s[0:index], s[index+1:]
}

// IsRealFunc checks the given function as taken from runtime.Frame.Function and determines if it is the real calling function. EG not from an internal call in a logging package
func IsRealFunc(name string) bool {
	_, funcname := RPartition(name, ".")
	if funcNames[funcname] {
		return false
	}
	subMod, modName := RPartition(name, "/")
	_ = subMod
	modName, _ = Partition(modName, ".")
	return !modNames[modName]
}

// GetRealFunc checks each stack fram to find the real calling function to get a useful file and line number
func GetRealFunc(pcs []uintptr) (string, string, int) {
	frames := runtime.CallersFrames(pcs)
	next := true
	var frame runtime.Frame
	for next {
		frame, next = frames.Next()
		if !IsRealFunc(frame.Function) {
			continue
		}
		return frame.Function, strings.ReplaceAll(frame.File, "gitea.narnian.us/lordwelch/comic-hasher/", "./"), frame.Line
	}
	return "", "", 0
}

func (l Logger) Log(level Level, msg string, args ...any) {
	pcs := make([]uintptr, 16) // just to make sure we don't run into any idiocy about function call depth
	n := runtime.Callers(2, pcs)
	pcs = pcs[0:n]
	// This should never actually happen
	loggerLevel, ok := LogLevels[Logger(strings.ToLower(string(l)))]
	if !ok {
		loggerLevel = LogLevels[ALL]
	}
	if level < loggerLevel {
		return
	}
	record := Record{
		logger: l,
		level:  level,
		pcs:    pcs,
		msg:    msg,
		args:   args,
	}
	if Diode == nil {
		stdlog.Println(format(LogFormat, record))
		return
	}
	Diode.Set(record)
}

// Println is Logger.Log(level, "", args...)
func (l Logger) Println(level Level, args ...any) {
	l.Log(level, "", args...)
}

// EnableNonBlocking logging please wait for 11 Milliseconds when exiting to ensure all logs are processed
func EnableNonBlocking(ctx context.Context, queueSize int) {
	Diode = NewManyToOne(ctx, queueSize, nil)
	go asyncLog(Diode)
}

// NewLogger creates a logger. Any aliases are additional names for the same logger, so two loggers that have the same alias can get their level set through a single name.
func NewLogger(name string, aliases ...string) Logger {
	if name == "" {
		name = "main"
	}
	lower := Logger(strings.ToLower(name))
	l := Logger(name)
	for _, alias := range aliases {
		if alias == "" {
			continue
		}
		a := Logger(strings.ToLower(alias))
		LoggerAliases[a] = append(LoggerAliases[a], lower)
		slices.Sort(LoggerAliases[a])
		LoggerAliases[a] = slices.Compact(LoggerAliases[a])
	}
	if _, ok := LogLevels[lower]; ok {
		return l
	}
	LogLevels[lower] = 0
	return l
}

// ALL is for setting the default log level. Do not use it to log directly
const ALL Logger = "ALL"

var defaultLogger = NewLogger("main")

// Log is Logger.Log for the "main" logger
func Log(level Level, msg string, stuff ...any) {
	defaultLogger.Log(level, msg, stuff...)
}

// Println is Logger.Println for the "main" logger
func Println(level Level, args ...any) {
	defaultLogger.Log(level, "", args...)
}
