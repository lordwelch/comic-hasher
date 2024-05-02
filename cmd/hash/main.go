package main

import (
	"flag"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"log"
	"os"
	"strings"

	_ "github.com/spakin/netpbm"

	"gitea.narnian.us/lordwelch/goimagehash"
	"github.com/anthonynsimon/bild/transform"
	_ "github.com/gen2brain/avif"
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

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
				if uint8(r) == 0x0015 && uint8(g) == 0x0013 && uint8(b) == 0x0012 {
					fmt.Fprintf(os.Stderr, "RGB: { %04x, %04x, %04x }\n", uint8(r), uint8(g), uint8(b))
				}
				fmt.Fprintf(str, "{ %04x, %04x, %04x }, ", uint8(r), uint8(g), uint8(b))
			}
		}
		str.WriteString("]\n")
	}
	return str.String()
}

func debugImage(im image.Image, width, height int) {
	// gray := image.NewGray(image.Rect(0, 0, im.Bounds().Dx(), im.Bounds().Dy()))
	// gray.Pix = transforms.Rgb2Gray(im)
	// i_resize := imaging.Resize(im, width, height, imaging.Linear)
	resized := transform.Resize(im, 8, 8, transform.Lanczos)
	r_gray := image.NewGray(image.Rect(0, 0, resized.Bounds().Dx(), resized.Bounds().Dy()))
	draw.Draw(r_gray, resized.Bounds(), resized, resized.Bounds().Min, draw.Src)

	// fmt.Fprintln(os.Stderr, "rgb")
	// fmt.Println(fmtImage(im))
	// fmt.Fprintln(os.Stderr, "grayscale")
	// fmt.Println(fmtImage(gray))
	// fmt.Println("resized")
	fmt.Println(fmtImage(r_gray))
}

func main() {
	imPath := flag.String("file", "", "image file to hash")
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
	im, format, err := image.Decode(file)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode Image: %s", err)
		log.Println(msg)
		return
	}

	if format == "webp" {
		im = goimagehash.FancyUpscale(im.(*image.YCbCr))
	}

	var (
		ahash *goimagehash.ImageHash
		dhash *goimagehash.ImageHash
		phash *goimagehash.ImageHash
	)

	ahash, err = goimagehash.AverageHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to ahash Image: %s", err)
		log.Println(msg)
		return
	}
	dhash, err = goimagehash.DifferenceHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to dhash Image: %s", err)
		log.Println(msg)
		return
	}
	phash, err = goimagehash.PerceptionHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to phash Image: %s", err)
		log.Println(msg)
		return
	}
	gray := goimagehash.ToGray(im)
	file2, err := os.Create("tmp.png")
	if err != nil {
		log.Printf("Failed to open file %s: %s", "tmp.png", err)
		return
	}
	err = png.Encode(file2, gray)
	if err != nil {
		panic(err)
	}
	file2.Close()
	debugImage(gray, 9, 8)

	fmt.Fprintf(os.Stderr, "ahash: %s\n", ahash.String())
	fmt.Fprintf(os.Stderr, "dhash: %s\n", dhash.String())
	fmt.Fprintf(os.Stderr, "phash: %s\n", phash.String())
}
