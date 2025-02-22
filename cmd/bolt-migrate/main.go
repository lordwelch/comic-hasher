package main

import (
	"fmt"
	"os"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
)

func main() {
	fmt.Printf("cv path: %s Sqlite path: %s Bolt path: %s\n", os.Args[1], os.Args[2], os.Args[3])
	sql, err := ch.OpenCHDBSqlite(os.Args[2], os.Args[1], false)
	if err != nil {
		panic(err)
	}
	db, err := ch.OpenCHDBBolt(os.Args[3], os.Args[1], false)
	if err != nil {
		panic(err)
	}
	paths, bad_urls := sql.Dump()
	fmt.Printf("Dumped %d %d", len(paths), len(bad_urls))
	db.Import(paths, bad_urls)
	// for _, path := range paths {
	// 	db.AddPath(filepath.Join(os.Args[1], path))
	// }
	// for _, url := range bad_urls {
	// 	db.AddURL(url)
	// }
	sql.Close()
	db.Close()
}
