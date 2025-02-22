package ch

type CHDB interface {
	// OpenCHDB(path string, comicvinePath string, deleteExisting bool) (CHDB, error)
	PathHashed(path string) bool
	PathDownloaded(path string) bool
	AddPath(path string)
	CheckURL(url string) bool
	AddURL(url string)
	Close() error
}
