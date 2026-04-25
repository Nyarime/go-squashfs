package main

import (
	"fmt"
	"os"

	squashfs "github.com/Nyarime/go-squashfs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test <squashfs|dir> [outdir|output.sqfs]")
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
		w := squashfs.NewWriter()
		err := w.CreateFromDir(os.Args[1], output)
		if err != nil {
			fmt.Println("Write error:", err)
			return
		}
		fmt.Printf("Created: %s\n", output)

		// Verify by reading back
		r, err := squashfs.OpenFile(output)
		if err != nil {
			fmt.Println("Verify error:", err)
			return
		}
		names, _ := r.ListRoot()
		fmt.Printf("Verify root: %v\n", names)
	} else {
		// Read mode
		r, err := squashfs.OpenFile(os.Args[1])
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
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
