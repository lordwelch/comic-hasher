module gitea.narnian.us/lordwelch/comic-hasher

go 1.22.1

toolchain go1.22.2

require (
	gitea.narnian.us/lordwelch/goimagehash v0.0.0-20240502010648-cb5a8237c420
	github.com/disintegration/imaging v1.6.3-0.20201218193011-d40f48ce0f09
	github.com/fmartingr/go-comicinfo/v2 v2.0.2
	github.com/mholt/archiver/v4 v4.0.0-alpha.8
	golang.org/x/image v0.7.0
)

require (
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/bodgit/plumbing v1.2.0 // indirect
	github.com/bodgit/sevenzip v1.3.0 // indirect
	github.com/bodgit/windows v1.0.0 // indirect
	github.com/connesc/cipherio v0.2.1 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/nwaples/rardecode/v2 v2.0.0-beta.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	go4.org v0.0.0-20200411211856-f5505b9728dd // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
)

require golang.org/x/text v0.14.0

replace golang.org/x/text v0.14.0 => /home/timmy/build/source/text/

replace gitea.narnian.us/lordwelch/goimagehash v0.0.0-20240502010648-cb5a8237c420 => ../goimagehash
