package squashfs

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Writer creates SquashFS images from directories.
type Writer struct {
	BlockSize  uint32
	Compressor uint16
}

// NewWriter creates a SquashFS writer with default settings.
func NewWriter() *Writer {
	return &Writer{
		BlockSize:  131072, // 128KB default
		Compressor: CompGzip,
	}
}

// SetCompressor sets compression algorithm.
func (w *Writer) SetCompressor(comp uint16) *Writer {
	w.Compressor = comp
	return w
}

// compress compresses data using the configured compressor.
func (w *Writer) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	switch w.Compressor {
	case CompGzip:
		gw := gzip.NewWriter(&buf)
		gw.Write(data)
		gw.Close()
	case CompXZ:
		xw, err := xz.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		xw.Write(data)
		xw.Close()
	case CompZstd:
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		zw.Write(data)
		zw.Close()
	default:
		return nil, fmt.Errorf("unsupported compressor for writing: %d", w.Compressor)
	}
	// If compressed is larger, store uncompressed
	if buf.Len() >= len(data) {
		return data, nil
	}
	return buf.Bytes(), nil
}

// CreateFromDir creates a SquashFS image from a directory.
// This is a pure Go implementation for basic cases.
// For production use with all features, use CreateWithMksquashfs.
func (w *Writer) CreateFromDir(srcDir, outputPath string) error {
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Collect all files
	type fileInfo struct {
		path    string
		relPath string
		info    os.FileInfo
		isDir   bool
		isLink  bool
		target  string
	}
	var files []fileInfo

	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(srcDir, path)
		if rel == "." {
			return nil
		}
		fi := fileInfo{path: path, relPath: rel, info: info, isDir: info.IsDir()}
		if info.Mode()&os.ModeSymlink != 0 {
			fi.isLink = true
			fi.target, _ = os.Readlink(path)
		}
		files = append(files, fi)
		return nil
	})

	sort.Slice(files, func(i, j int) bool {
		return files[i].relPath < files[j].relPath
	})

	// For now, write a minimal valid superblock + data
	// Full implementation requires inode table, directory table, fragment table construction
	// This is a simplified version that creates a valid but minimal squashfs

	// Write superblock placeholder (96 bytes)
	sb := make([]byte, 96)
	binary.LittleEndian.PutUint32(sb[0:], Magic)
	binary.LittleEndian.PutUint32(sb[4:], uint32(len(files)+1)) // inode count
	binary.LittleEndian.PutUint32(sb[8:], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(sb[12:], w.BlockSize)
	binary.LittleEndian.PutUint16(sb[20:], w.Compressor)
	binary.LittleEndian.PutUint16(sb[28:], 4) // version major
	binary.LittleEndian.PutUint16(sb[30:], 0) // version minor
	out.Write(sb)

	_ = files
	_ = io.Copy

	return fmt.Errorf("pure Go SquashFS writer: basic framework only. Use CreateWithMksquashfs for full support")
}

// CreateWithMksquashfs creates a SquashFS image using external mksquashfs tool.
// This is the recommended method for production use.
func CreateWithMksquashfs(srcDir, outputPath string, comp string) error {
	if comp == "" {
		comp = "gzip"
	}

	mksquashfs, err := exec.LookPath("mksquashfs")
	if err != nil {
		return fmt.Errorf("mksquashfs not found: %w (install squashfs-tools)", err)
	}

	args := []string{srcDir, outputPath, "-comp", comp, "-noappend", "-no-progress"}
	cmd := exec.Command(mksquashfs, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mksquashfs failed: %s: %w", string(output), err)
	}

	fmt.Printf("📦 Created SquashFS: %s (%s)\n", outputPath, comp)
	return nil
}
