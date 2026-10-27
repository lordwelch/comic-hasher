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

var LogLevels = map[Logger]Level{}

var LoggerAliases = map[Logger][]Logger{}

func Aliases() []string {
	aliases := make([]string, 0, len(LoggerAliases))
	for alias := range LoggerAliases {
		aliases = append(aliases, string(alias))
	}
	return aliases
}

func applyLevel(name Logger, level Level) {
	loggers, isAlias := LoggerAliases[name]
	if isAlias {
		for _, logger := range loggers {
			LogLevels[logger] = level
		}
		return
	}
	LogLevels[name] = level
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

// Logger Use NewLogger
type Logger string

const (
	Trace    Level = -5   // Trace
	Debug    Level = -3   // Debug
	Verbose2 Level = -2   // More Verbose
	Verbose  Level = -1   // Verbose
	Standard Level = 0    // Standard
	Required Level = 1    // Required
	Fatal    Level = 9999 // Fatal
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
	items := strings.SplitSeq(strings.ToLower(s), ",")
	for item := range items {
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
		applyLevel(logger, (*f)[logger])
	}
	return nil
}

var LevelNames = map[string]Level{
	"trace":    Trace,
	"debug":    Debug,
	"verbose2": Verbose2,
	"verbose":  Verbose,
	"standard": Standard,
	"required": Required,
	"fatal":    Fatal,
}

var Levels = map[Level]string{
	Trace:    "trace",
	Debug:    "debug",
	Verbose2: "verbose2",
	Verbose:  "verbose",
	Standard: "standard",
	Required: "required",
	Fatal:    "fatal",
}

var tokens = []string{
	"{level}",
	"{message}",
	"{filename}",
	"{line}",
	"{function}",
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

func Partition(s string, sep string) (string, string) {
	index := strings.Index(s, sep)
	if index < 0 {
		return s, ""
	}
	return s[0:index], s[index+1:]
}

func RPartition(s string, sep string) (string, string) {
	index := strings.LastIndex(s, sep)
	if index < 0 {
		return "", s
	}
	return s[0:index], s[index+1:]
}

func RealFunc(name string) bool {
	_, funcname := RPartition(name, ".")
	if funcNames[funcname] {
		return false
	}
	subMod, modName := RPartition(name, "/")
	_ = subMod
	modName, _ = Partition(modName, ".")
	return !modNames[modName]
}

func GetRealFunc(pcs []uintptr) (string, string, int) {
	frames := runtime.CallersFrames(pcs)
	next := true
	var frame runtime.Frame
	for next {
		frame, next = frames.Next()
		if !RealFunc(frame.Function) {
			continue
		}
		return frame.Function, strings.ReplaceAll(frame.File, "gitea.narnian.us/lordwelch/comic-hasher/", "./"), frame.Line
	}
	return "", "", 0
}

func (l Logger) Log(level Level, msg string, stuff ...any) {
	pcs := make([]uintptr, 16) // just to make sure we don't run into any idiocy about function call depth
	n := runtime.Callers(2, pcs)
	pcs = pcs[0:n]
	if level < LogLevels[l] && level < LogLevels[ALL] {
		return
	}
	// fmt.Println("allowing log record through", Record{
	// 	level: level,
	// 	pcs:   pcs,
	// 	msg:   msg,
	// 	args:  stuff,
	// })
	record := Record{
		logger: l,
		level:  level,
		pcs:    pcs,
		msg:    msg,
		args:   stuff,
	}
	if Diode == nil {
		stdlog.Println(format(LogFormat, record))
		return
	}
	Diode.Set(record)
}

func (l Logger) Println(level Level, args ...any) {
	l.Log(level, "", args...)
}

func EnableNonBlocking(ctx context.Context, queueSize int) {
	Diode = NewManyToOne(ctx, queueSize, nil)
	go asyncLog(ctx, Diode)
}

// NewLogger creates a logger. Any aliases are additional names that select the
// same logger, so two loggers that select the same alias can get their level set through a single name.
func NewLogger(name string, aliases ...string) Logger {
	l := Logger(strings.ToLower(name))
	LogLevels[l] = 0
	for _, alias := range aliases {
		a := Logger(strings.ToLower(alias))
		LoggerAliases[a] = append(LoggerAliases[a], l)
	}
	return l
}

// ALL is the name that selects every logger.
const ALL Logger = "ALL"

var defaultLogger = NewLogger("main")

func Log(level Level, msg string, stuff ...any) {
	defaultLogger.Log(level, msg, stuff...)
}

func Println(level Level, args ...any) {
	defaultLogger.Log(level, "", args...)
}
