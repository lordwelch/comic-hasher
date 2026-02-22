module gitea.narnian.us/lordwelch/comic-hasher

go 1.23.0

toolchain go1.24.0

// Main comic-hasher
require (
	gitea.narnian.us/lordwelch/goimagehash v0.0.0-20250130004139-e91c39c79e0d
	github.com/disintegration/imaging v1.6.3-0.20201218193011-d40f48ce0f09
	github.com/json-iterator/go v1.1.12
	github.com/kr/pretty v0.2.1
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	go.etcd.io/bbolt v1.4.0
	golang.org/x/exp v0.0.0-20250218142911-aa4b98e5adaa
	golang.org/x/image v0.25.0
)

// Storage types
require (
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/ncruces/go-sqlite3 v0.26.0
	gonum.org/v1/gonum v0.16.0
	modernc.org/sqlite v1.35.0
)

// other commands
require golang.org/x/text v0.25.0

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	modernc.org/libc v1.61.13 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.8.2 // indirect
)
