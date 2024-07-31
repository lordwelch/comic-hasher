package main

import (
	"fmt"
	"strings"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

func main() {
	c := collate.New(language.English, collate.Loose, collate.Numeric, collate.Force)
	list := []string{
		"11.jpg",
		"12.jpg",
		"2.jpg",
		"99999999999999999.jpg",
		"02.jpg",
		"00.jpg",
		"0.jpg",
		"00.jpg",
		"1.jpg",
		"01.jpg",
		"Page3.gif",
		"page0.jpg",
		"Page1.jpeg",
		"Page2.png",
		"!cover.jpg", // Depending on locale punctuation or numbers might come first (Linux)
		"page4.webp",
		"page10.jpg",
	}
	c.SortStrings(list)
	fmt.Println(strings.Join(list, "\n"))
}
