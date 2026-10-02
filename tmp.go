//go:build main

package main

import (
	"fmt"
	"time"
)

func main() {
	tmp := make([]string, 0, 932456)
	for range 932460 {
		tmp = append(tmp, "comicvine.gamespot.com:123456")
	}
	fmt.Println(len(tmp))
	time.Sleep(time.Minute)
}
