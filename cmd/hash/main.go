package main

import (
	"bufio"
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"log"
	"os"
	"strings"

	_ "golang.org/x/image/webp"

	ch "gitea.narnian.us/lordwelch/comic-hasher"
	"gitea.narnian.us/lordwelch/goimagehash"
)

func init() {
	// image.RegisterFormat("jpeg", "\xff\xd8", func(r io.Reader) (image.Image, error){return jpeg.Decode(r, &jpeg.DecoderOptions{
	// 	DisableFancyUpsampling: false,
	// 	DisableBlockSmoothing: false,
	// 	DCTMethod: jpeg.DCTFloat,
	// })}, jpeg.DecodeConfig)
}

func saveImage(im image.Image, name string) {
	file, err := os.Create(name)
	if err != nil {
		log.Printf("Failed to open file %s: %s", "tmp.png", err)
		return
	}
	err = png.Encode(file, im)
	if err != nil {
		panic(err)
	}
	file.Close()
}

func fmtImage(im image.Image) string {
	gray, ok := im.(*image.Gray)
	str := &strings.Builder{}

	for y := 0; y < im.Bounds().Dy(); y++ {
		str.WriteString("[ ")
		for x := 0; x < im.Bounds().Dx(); x++ {
			if ok {
				fmt.Fprintf(str, "%03d, ", gray.GrayAt(x, y).Y)
			} else {
				col := im.At(x, y)
				r, g, b, _ := col.RGBA()
				fmt.Fprintf(str, "{ %03d, %03d, %03d }, ", uint8(r>>8), uint8(g>>8), uint8(b>>8))
			}
		}
		str.WriteString("]\n")
	}
	return str.String()
}

func debugImage(im image.Image, width, height int) {
	gray := goimagehash.ToGray(im, nil)
	resized := goimagehash.Resize(gray, width, height, nil)

	saveImage(im, "go.rgb.png")
	log.Println("rgb")
	log.Println(fmtImage(im))

	saveImage(gray, "go.gray.png")
	log.Println("gray")
	log.Println(fmtImage(gray))

	saveImage(resized, "go.resized.png")
	log.Println("resized")
	log.Println(fmtImage(resized))
}

func main() {
	log.SetFlags(0)
	imPath := flag.String("file", "", "image file to hash")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()
	if imPath == nil || *imPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	file, err := os.Open(*imPath)
	if err != nil {
		log.Printf("Failed to open file %s: %s", *imPath, err)
		return
	}
	defer file.Close()
	im, format, err := image.Decode(bufio.NewReader(file))
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		log.Println(msg)
		return
	}
	debugim := im
	if format == "webp" {
		debugim = goimagehash.FancyUpscale(im.(*image.YCbCr))
	}

	if *debug {
		debugImage(debugim, 8, 8)
	}

	hash := ch.HashImage(ch.Im{Im: im, Format: format, Domain: ch.Source(ch.ComicVine), ID: "nothing"})

	fmt.Println("ahash: ", hash.Ahash.BinString())
	fmt.Println("dhash: ", hash.Dhash.BinString())
	fmt.Println("phash: ", hash.Phash.BinString())
}
