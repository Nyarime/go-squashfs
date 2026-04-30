package main

import (
	"fmt"
	"os"
	"strings"

	squashfs "github.com/Nyarime/go-squashfs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test <squashfs|dir> [outdir|output.sqfs] [gzip|zstd|xz]")
		return
	}

	fi, err := os.Stat(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if fi.IsDir() {
		// Write mode
		output := "output.squashfs"
		if len(os.Args) >= 3 {
			output = os.Args[2]
		}
		comp := "gzip"
		if len(os.Args) >= 4 {
			comp = os.Args[3]
		}

		w := squashfs.NewWriter()
		switch strings.ToLower(comp) {
		case "zstd":
			w.SetCompressor(squashfs.CompZstd)
		case "xz":
			w.SetCompressor(squashfs.CompXZ)
		case "gzip":
			// default
		}

		err := w.CreateFromDir(os.Args[1], output)
		if err != nil {
			fmt.Println("Write error:", err)
			return
		}
		fmt.Printf("Created: %s (comp=%s)\n", output, comp)

		// Verify by reading back
		r, err := squashfs.OpenFile(output)
		if err != nil {
			fmt.Println("Verify error:", err)
			return
		}
		defer r.Close()
		fmt.Println("Verify:", r.String())
		names, _ := r.ListRoot()
		fmt.Printf("Verify root: %v\n", names)
	} else {
		// Read mode
		r, err := squashfs.OpenFile(os.Args[1])
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer r.Close()
		fmt.Println(r.String())
		names, _ := r.ListRoot()
		fmt.Printf("Root: %v\n", names)

		outDir := "/tmp/go-squashfs-test"
		if len(os.Args) >= 3 {
			outDir = os.Args[2]
		}
		count, err := r.ExtractTo(outDir)
		fmt.Printf("Extracted: %d files (err=%v)\n", count, err)
	}
}
