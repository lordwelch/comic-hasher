package main

import (
	"flag"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"

	// "github.com/pixiv/go-libjpeg/jpeg"
	"image/png"
	"log"
	"os"
	"strings"

	"gitea.narnian.us/lordwelch/goimagehash"
	"gitea.narnian.us/lordwelch/goimagehash/transforms"
	"github.com/anthonynsimon/bild/transform"
	ih "gitea.narnian.us/lordwelch/image-hasher"
	_ "github.com/gen2brain/avif"
	_ "github.com/spakin/netpbm"
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

func init() {
	// image.RegisterFormat("jpeg", "\xff\xd8", func(r io.Reader) (image.Image, error){return jpeg.Decode(r, &jpeg.DecoderOptions{
	// 	DisableFancyUpsampling: false,
	// 	DisableBlockSmoothing: false,
	// 	DCTMethod: jpeg.DCTFloat,
	// })}, jpeg.DecodeConfig)

}

func ToGray(img image.Image, pix []uint8) *image.Gray {
	c := img.Bounds().Dx() * img.Bounds().Dy()
	if cap(pix) < c {
		pix = append([]byte(nil), make([]byte, c)...)
	}
	pix = pix[:c]
	gray := &image.Gray{
		Pix:    transforms.Rgb2Gray(img, pix),
		Stride: img.Bounds().Dx(),
		Rect:   img.Bounds(),
	}
	return gray
}

func resize(img image.Image, w, h int) *image.Gray {
	resized := transform.Resize(img, w, h, transform.Lanczos)
	r_gray := image.NewGray(image.Rect(0, 0, resized.Bounds().Dx(), resized.Bounds().Dy()))
	draw.Draw(r_gray, resized.Bounds(), resized, resized.Bounds().Min, draw.Src)
	return r_gray
}

func save_image(im image.Image, name string) {
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
	gray := ToGray(im, nil)
	resized := resize(gray, width, height)

	log.Println("rgb")
	log.Println(fmtImage(im))
	save_image(im, "go.rgb.png")
	log.Println("gray")
	log.Println(fmtImage(gray))
	save_image(gray, "go.gray.png")
	log.Println("resized")
	log.Println(fmtImage(resized))
	save_image(resized, "go.resized.png")
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

	debugImage(im, 8, 8)

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
		msg := fmt.Sprintf("Failed to ahash Image: %s", err)
		log.Println(msg)
		return
	}

	phash, err = goimagehash.PerceptionHash(im)
	if err != nil {
		msg := fmt.Sprintf("Failed to ahash Image: %s", err)
		log.Println(msg)
		return
	}

	fmt.Println("ahash: ", ahash.BinString())
	fmt.Println("dhash: ", dhash.BinString())
	fmt.Println("phash: ", phash.BinString())
}
