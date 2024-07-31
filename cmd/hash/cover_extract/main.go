package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fmartingr/go-comicinfo/v2"

	"github.com/mholt/archiver/v4"
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

func main() {
	c := collate.New(language.English, collate.Loose, collate.Numeric, collate.Force)
	fileArchive := flag.String("file", "", "archive to extract cover")
	flag.Parse()
	if fileArchive == nil || *fileArchive == "" {
		flag.Usage()
		os.Exit(1)
	}

	file, err := os.Open(*fileArchive)
	if err != nil {
		log.Printf("Failed to open file %s: %s", *fileArchive, err)
		return
	}
	unrar := archiver.Rar{}
	fileList := []string{}
	err = unrar.Extract(context.TODO(), file, nil, func(ctx context.Context, f archiver.File) error {
		if !strings.HasSuffix(f.NameInArchive, ".xml") {
			fileList = append(fileList, f.NameInArchive)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		panic(err)
	}
	c.SortStrings(fileList)
	var image []byte
	var issue_id string
	var files = []string{"ComicInfo.xml", fileList[0]}
	fmt.Printf("Extracting %s\n", fileList[0])
	err = unrar.Extract(context.TODO(), file, files, func(ctx context.Context, f archiver.File) error {
		r, err := f.Open()
		if err != nil {
			return err
		}
		if f.Name() == "ComicInfo.xml" {
			ci, err := comicinfo.Read(r)
			if err != nil {
				return err
			}
			parts := strings.Split(strings.TrimRight(ci.Web, "/"), "/")
			ids := strings.Split(parts[len(parts)-1], "-")
			issue_id = ids[1]
		} else {
			image, err = io.ReadAll(r)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	file.Close()
	file, err = os.Create(*fileArchive + "." + issue_id + ".image")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	_, err = file.Write(image)
	if err != nil {
		panic(err)
	}
	// os.Remove(*fileArchive)
	// fmt.Println("removed " + *fileArchive)
}
