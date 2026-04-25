package main

import (
	"fmt"
	"os"

	squashfs "github.com/Nyarime/go-squashfs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test <squashfs-file> [outdir]")
		return
	}

	r, err := squashfs.OpenFile(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(r.String())

	names, err := r.ListRoot()
	if err != nil {
		fmt.Println("ListRoot error:", err)
		return
	}
	fmt.Printf("Root: %v\n", names)

	outDir := "/tmp/go-squashfs-test"
	if len(os.Args) >= 3 {
		outDir = os.Args[2]
	}

	count, err := r.ExtractTo(outDir)
	fmt.Printf("Extracted: %d files (err=%v)\n", count, err)
}
