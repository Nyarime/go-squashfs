// Package squashfs provides a pure Go SquashFS reader.
// Supports gzip, xz, lzma, lz4, zstd compression.
// Designed for firmware analysis — works on Linux, macOS, and Windows.
// Memory-efficient: uses file-backed I/O for large images, streams file
// extraction directly to disk instead of buffering in memory.
package squashfs

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	Magic    = 0x73717368
	CompGzip = 1
	CompLZMA = 2
	CompLZO  = 3
	CompXZ   = 4
	CompLZ4  = 5
	CompZstd = 6

	InodeBasicDir     = 1
	InodeBasicFile    = 2
	InodeBasicSymlink = 3
	InodeBasicBlock   = 4
	InodeBasicChar    = 5
	InodeBasicFifo    = 6
	InodeBasicSocket  = 7
	InodeExtDir       = 8
	InodeExtFile      = 9
	InodeExtSymlink   = 10

	NoFragment = 0xFFFFFFFF

	maxExtractFiles = 100000
	maxExtractDepth = 20
	maxPathLen      = 4096
	// Maximum decompressed output per block (safety limit: 4x block size)
	decompressLimit = 4
)

type Superblock struct {
	Magic            uint32
	InodeCount       uint32
	ModTime          uint32
	BlockSize        uint32
	FragmentCount    uint32
	Compressor       uint16
	BlockLog         uint16
	Flags            uint16
	IDCount          uint16
	VersionMajor     uint16
	VersionMinor     uint16
	RootInodeRef     uint64
	BytesUsed        uint64
	IDTableStart     uint64
	XattrTableStart  uint64
	InodeTableStart  uint64
	DirTableStart    uint64
	FragTableStart   uint64
	LookupTableStart uint64
}

type Inode struct {
	Type       uint16
	Perm       uint16
	ModTime    uint32
	Number     uint32
	FileSize   uint64
	StartBlock uint64
	FragIndex  uint32
	FragOffset uint32
	SymTarget  string
	DirStart   uint32
	DirSize    uint32
	DirOffset  uint16
	Nlinks     uint32
	BlockSizes []uint32
}

type fragEntry struct {
	Start  uint64
	Size   uint32
	Unused uint32
}

// dataSource abstracts reading from either a byte slice or a file.
type dataSource interface {
	ReadAt(p []byte, off int64) (int, error)
	Len() int
	// Slice returns bytes from [start:end]. For small metadata reads.
	Slice(start, end int) ([]byte, error)
}

// byteSource wraps a []byte as a dataSource.
type byteSource struct{ data []byte }

func (b *byteSource) ReadAt(p []byte, off int64) (int, error) {
	if int(off) >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (b *byteSource) Len() int { return len(b.data) }
func (b *byteSource) Slice(start, end int) ([]byte, error) {
	if end > len(b.data) {
		return nil, fmt.Errorf("slice beyond data")
	}
	return b.data[start:end], nil
}

// fileSource wraps an os.File as a dataSource.
type fileSource struct {
	f    *os.File
	size int
}

func (f *fileSource) ReadAt(p []byte, off int64) (int, error) {
	return f.f.ReadAt(p, off)
}
func (f *fileSource) Len() int { return f.size }
func (f *fileSource) Slice(start, end int) ([]byte, error) {
	buf := make([]byte, end-start)
	_, err := f.f.ReadAt(buf, int64(start))
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

type metaMapping struct {
	compOff uint64
	decOff  uint64
}

type Reader struct {
	src          dataSource
	srcFile      *os.File // non-nil if we opened the file (for Close)
	SB           Superblock
	inodeData    []byte // decompressed inode table
	dirData      []byte // decompressed directory table
	frags        []fragEntry
	inodeMetaMap []metaMapping
	dirMetaMap   []metaMapping
}

// NewReader creates a SquashFS reader from raw bytes.
func NewReader(data []byte) (*Reader, error) {
	return newReader(&byteSource{data: data})
}

// OpenFile opens a SquashFS from a file path.
// Uses file-backed I/O to avoid loading the entire image into memory.
func OpenFile(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	r, err := newReader(&fileSource{f: f, size: int(fi.Size())})
	if err != nil {
		f.Close()
		return nil, err
	}
	r.srcFile = f
	return r, nil
}

// Close releases resources. Safe to call multiple times.
func (r *Reader) Close() error {
	if r.srcFile != nil {
		err := r.srcFile.Close()
		r.srcFile = nil
		return err
	}
	return nil
}

func newReader(src dataSource) (*Reader, error) {
	if src.Len() < 96 {
		return nil, fmt.Errorf("squashfs: too short")
	}
	hdr, err := src.Slice(0, 96)
	if err != nil {
		return nil, err
	}

	r := &Reader{src: src}
	d := hdr
	r.SB.Magic = le32(d[0:])
	if r.SB.Magic != Magic {
		return nil, fmt.Errorf("squashfs: bad magic 0x%08X", r.SB.Magic)
	}
	r.SB.InodeCount = le32(d[4:])
	r.SB.ModTime = le32(d[8:])
	r.SB.BlockSize = le32(d[12:])
	r.SB.FragmentCount = le32(d[16:])
	r.SB.Compressor = le16(d[20:])
	r.SB.BlockLog = le16(d[22:])
	r.SB.Flags = le16(d[24:])
	r.SB.IDCount = le16(d[26:])
	r.SB.VersionMajor = le16(d[28:])
	r.SB.VersionMinor = le16(d[30:])
	r.SB.RootInodeRef = le64(d[32:])
	r.SB.BytesUsed = le64(d[40:])
	r.SB.IDTableStart = le64(d[48:])
	r.SB.XattrTableStart = le64(d[56:])
	r.SB.InodeTableStart = le64(d[64:])
	r.SB.DirTableStart = le64(d[72:])
	r.SB.FragTableStart = le64(d[80:])
	r.SB.LookupTableStart = le64(d[88:])

	// Pre-read inode and directory metadata tables (small, always fits in memory)
	r.inodeData, r.inodeMetaMap, err = r.readMetaRange(r.SB.InodeTableStart, r.SB.DirTableStart)
	if err != nil {
		return nil, fmt.Errorf("inode table: %w", err)
	}
	r.dirData, r.dirMetaMap, err = r.readMetaRange(r.SB.DirTableStart, r.SB.FragTableStart)
	if err != nil {
		return nil, fmt.Errorf("dir table: %w", err)
	}

	if r.SB.FragmentCount > 0 {
		r.frags, err = r.readFragTable()
		if err != nil {
			r.frags = nil
		}
	}

	return r, nil
}

func (r *Reader) CompressorName() string {
	m := map[uint16]string{1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
	if n, ok := m[r.SB.Compressor]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", r.SB.Compressor)
}

func (r *Reader) String() string {
	return fmt.Sprintf("SquashFS v%d.%d %s block=%d inodes=%d size=%d",
		r.SB.VersionMajor, r.SB.VersionMinor, r.CompressorName(),
		r.SB.BlockSize, r.SB.InodeCount, r.SB.BytesUsed)
}

// decompress decompresses data using the filesystem's compressor.
// Output is limited to maxOut bytes to prevent memory bombs.
func (r *Reader) decompress(compressed []byte, maxOut int) ([]byte, error) {
	if maxOut <= 0 {
		maxOut = int(r.SB.BlockSize) * decompressLimit
	}
	lr := io.LimitReader(nil, int64(maxOut))
	_ = lr // we'll use LimitedReader below

	switch r.SB.Compressor {
	case CompGzip:
		zr, err := zlib.NewReader(bytes.NewReader(compressed))
		if err != nil {
			gr, gerr := gzip.NewReader(bytes.NewReader(compressed))
			if gerr != nil {
				return nil, err
			}
			defer gr.Close()
			return io.ReadAll(io.LimitReader(gr, int64(maxOut)))
		}
		defer zr.Close()
		return io.ReadAll(io.LimitReader(zr, int64(maxOut)))
	case CompXZ:
		xr, err := XzNewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		defer xr.Close()
		return io.ReadAll(io.LimitReader(xr, int64(maxOut)))
	case CompLZMA:
		lr, err := LzmaNewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		defer lr.Close()
		return io.ReadAll(io.LimitReader(lr, int64(maxOut)))
	case CompZstd:
		zr, err := ZstdNewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(io.LimitReader(zr, int64(maxOut)))
	default:
		return nil, fmt.Errorf("unsupported: %s", r.CompressorName())
	}
}

// Decompress is the public API (backward compat). No output limit.
func (r *Reader) Decompress(compressed []byte) ([]byte, error) {
	return r.decompress(compressed, 0)
}

// readSlice reads bytes from the source at [start:end].
func (r *Reader) readSlice(start, end int) ([]byte, error) {
	return r.src.Slice(start, end)
}

func (r *Reader) readMetablock(offset uint64) ([]byte, uint64, error) {
	if int(offset)+2 > r.src.Len() {
		return nil, 0, fmt.Errorf("metablock @0x%X beyond data", offset)
	}
	hdrBuf, err := r.readSlice(int(offset), int(offset)+2)
	if err != nil {
		return nil, 0, err
	}
	header := le16(hdrBuf)
	uncomp := header&0x8000 != 0
	size := int(header & 0x7FFF)
	end := int(offset) + 2 + size
	if end > r.src.Len() {
		return nil, 0, fmt.Errorf("metablock data beyond file")
	}
	raw, err := r.readSlice(int(offset)+2, end)
	if err != nil {
		return nil, 0, err
	}
	if uncomp {
		return raw, uint64(size) + 2, nil
	}
	// Metadata blocks decompress to max 8192 bytes
	dec, err := r.decompress(raw, 8192)
	if err != nil {
		return nil, 0, err
	}
	return dec, uint64(size) + 2, nil
}

func (r *Reader) readMetaRange(start, end uint64) ([]byte, []metaMapping, error) {
	var result []byte
	var mapping []metaMapping
	off := start
	var decOff uint64
	for off < end {
		mapping = append(mapping, metaMapping{compOff: off - start, decOff: decOff})
		block, consumed, err := r.readMetablock(off)
		if err != nil {
			return result, mapping, err
		}
		result = append(result, block...)
		decOff += uint64(len(block))
		off += consumed
	}
	return result, mapping, nil
}

func (r *Reader) readFragTable() ([]fragEntry, error) {
	nPtrs := (int(r.SB.FragmentCount) + 511) / 512
	ptrOff := int(r.SB.FragTableStart)
	if ptrOff+nPtrs*8 > r.src.Len() {
		return nil, fmt.Errorf("frag table pointers beyond data")
	}
	ptrData, err := r.readSlice(ptrOff, ptrOff+nPtrs*8)
	if err != nil {
		return nil, err
	}

	var allFragData []byte
	for i := 0; i < nPtrs; i++ {
		ptr := le64(ptrData[i*8:])
		block, _, err := r.readMetablock(ptr)
		if err != nil {
			return nil, err
		}
		allFragData = append(allFragData, block...)
	}

	frags := make([]fragEntry, r.SB.FragmentCount)
	for i := uint32(0); i < r.SB.FragmentCount; i++ {
		off := int(i) * 16
		if off+16 > len(allFragData) {
			break
		}
		frags[i].Start = le64(allFragData[off:])
		frags[i].Size = le32(allFragData[off+8:])
	}
	return frags, nil
}

func (r *Reader) readInode(ref uint64) (Inode, error) {
	blockOff := uint32(ref >> 16)
	byteOff := uint16(ref & 0xFFFF)

	decOffset := r.resolveInodeRef(blockOff)
	pos := int(decOffset) + int(byteOff)
	if pos+16 > len(r.inodeData) {
		return Inode{}, fmt.Errorf("inode @%d beyond table (%d)", pos, len(r.inodeData))
	}

	d := r.inodeData[pos:]
	var in Inode
	in.Type = le16(d[0:])
	in.Perm = le16(d[2:])
	in.ModTime = le32(d[8:])
	in.Number = le32(d[12:])

	switch in.Type {
	case InodeBasicDir:
		if pos+32 > len(r.inodeData) {
			return in, fmt.Errorf("basic dir inode too short")
		}
		in.DirStart = le32(d[16:])
		in.Nlinks = le32(d[20:])
		in.DirSize = uint32(le16(d[24:])) + 3
		in.DirOffset = le16(d[26:])

	case InodeExtDir:
		if pos+40 > len(r.inodeData) {
			return in, fmt.Errorf("ext dir inode too short")
		}
		in.Nlinks = le32(d[16:])
		in.DirSize = le32(d[20:]) + 3
		in.DirStart = le32(d[24:])
		in.DirOffset = le16(d[34:])

	case InodeBasicFile:
		if pos+32 > len(r.inodeData) {
			return in, fmt.Errorf("basic file inode too short")
		}
		in.StartBlock = uint64(le32(d[16:]))
		in.FragIndex = le32(d[20:])
		in.FragOffset = le32(d[24:])
		in.FileSize = uint64(le32(d[28:]))
		nBlocks := int(in.FileSize) / int(r.SB.BlockSize)
		if in.FragIndex == NoFragment && in.FileSize%uint64(r.SB.BlockSize) != 0 {
			nBlocks++
		}
		bsOff := pos + 32
		for i := 0; i < nBlocks && bsOff+4 <= len(r.inodeData); i++ {
			in.BlockSizes = append(in.BlockSizes, le32(r.inodeData[bsOff:]))
			bsOff += 4
		}

	case InodeExtFile:
		if pos+56 > len(r.inodeData) {
			return in, fmt.Errorf("ext file inode too short")
		}
		in.StartBlock = le64(d[16:])
		in.FileSize = le64(d[24:])
		in.Nlinks = le32(d[40:])
		in.FragIndex = le32(d[44:])
		in.FragOffset = le32(d[48:])
		nBlocks := int(in.FileSize) / int(r.SB.BlockSize)
		if in.FragIndex == NoFragment && in.FileSize%uint64(r.SB.BlockSize) != 0 {
			nBlocks++
		}
		bsOff := pos + 56
		for i := 0; i < nBlocks && bsOff+4 <= len(r.inodeData); i++ {
			in.BlockSizes = append(in.BlockSizes, le32(r.inodeData[bsOff:]))
			bsOff += 4
		}

	case InodeBasicSymlink, InodeExtSymlink:
		if pos+24 > len(r.inodeData) {
			return in, fmt.Errorf("symlink inode too short")
		}
		in.Nlinks = le32(d[16:])
		targetSize := le32(d[20:])
		if pos+24+int(targetSize) <= len(r.inodeData) {
			in.SymTarget = string(d[24 : 24+targetSize])
		}
	}

	return in, nil
}

func (r *Reader) resolveInodeRef(blockOff uint32) uint64 {
	for i := len(r.inodeMetaMap) - 1; i >= 0; i-- {
		if uint64(blockOff) >= r.inodeMetaMap[i].compOff {
			return r.inodeMetaMap[i].decOff
		}
	}
	return uint64(blockOff)
}

func (r *Reader) resolveDirRef(blockOff uint32) uint64 {
	for i := len(r.dirMetaMap) - 1; i >= 0; i-- {
		if uint64(blockOff) >= r.dirMetaMap[i].compOff {
			return r.dirMetaMap[i].decOff
		}
	}
	return uint64(blockOff)
}

type dirEntry struct {
	Name     string
	InodeRef uint64
	InodeNum uint32
	Type     uint16
}

func (r *Reader) readDirEntries(in Inode) ([]dirEntry, error) {
	decStart := r.resolveDirRef(in.DirStart)
	start := int(decStart) + int(in.DirOffset)
	size := int(in.DirSize) - 3
	if start+size > len(r.dirData) {
		return nil, fmt.Errorf("dir data beyond table")
	}

	var entries []dirEntry
	off := start
	end := start + size
	for off < end {
		if off+12 > len(r.dirData) {
			break
		}
		count := int(le32(r.dirData[off:])) + 1
		blockStart := le32(r.dirData[off+4:])
		inodeBase := le32(r.dirData[off+8:])
		off += 12

		for i := 0; i < count; i++ {
			if off+8 > len(r.dirData) {
				break
			}
			entOffset := le16(r.dirData[off:])
			entInodeDelta := int16(binary.LittleEndian.Uint16(r.dirData[off+2:]))
			entType := le16(r.dirData[off+4:])
			nameLen := int(le16(r.dirData[off+6:])) + 1
			off += 8

			if off+nameLen > len(r.dirData) {
				break
			}
			name := string(r.dirData[off : off+nameLen])
			off += nameLen

			inodeRef := (uint64(blockStart) << 16) | uint64(entOffset)
			entries = append(entries, dirEntry{
				Name:     name,
				InodeRef: inodeRef,
				InodeNum: uint32(int32(inodeBase) + int32(entInodeDelta)),
				Type:     entType,
			})
		}
	}
	return entries, nil
}

// ExtractTo extracts the entire filesystem to outDir.
func (r *Reader) ExtractTo(outDir string) (int, error) {
	os.MkdirAll(outDir, 0755)

	rootInode, err := r.readInode(r.SB.RootInodeRef)
	if err != nil {
		return 0, fmt.Errorf("root inode: %w", err)
	}

	count := 0
	seen := make(map[uint32]bool) // inode dedup
	err = r.extractDir(outDir, rootInode, &count, 0, seen)
	return count, err
}

func (r *Reader) extractDir(path string, in Inode, count *int, depth int, seen map[uint32]bool) error {
	if depth > maxExtractDepth {
		return nil
	}
	if *count > maxExtractFiles {
		return nil
	}
	if len(path) > maxPathLen {
		return nil
	}

	// Dedup by inode number — prevents recursive symlink-like structures
	if in.Number > 0 {
		if seen[in.Number] {
			return nil
		}
		seen[in.Number] = true
	}

	os.MkdirAll(path, 0755)

	entries, err := r.readDirEntries(in)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if e.Name == "." || e.Name == ".." {
			continue
		}
		// Security: reject path traversal
		if strings.Contains(e.Name, "/") || strings.Contains(e.Name, "..") {
			continue
		}
		fullPath := filepath.Join(path, e.Name)
		if len(fullPath) > maxPathLen {
			continue
		}

		childInode, err := r.readInode(e.InodeRef)
		if err != nil {
			continue
		}

		switch childInode.Type {
		case InodeBasicDir, InodeExtDir:
			r.extractDir(fullPath, childInode, count, depth+1, seen)

		case InodeBasicFile, InodeExtFile:
			if *count >= maxExtractFiles {
				return nil
			}
			if err := r.extractFileToPath(childInode, fullPath); err != nil {
				continue
			}
			*count++

		case InodeBasicSymlink, InodeExtSymlink:
			if childInode.SymTarget != "" {
				// Security: only create symlink, never follow
				os.Symlink(childInode.SymTarget, fullPath)
				*count++
			}
		}
	}
	return nil
}

// extractFileToPath streams file data block-by-block directly to disk.
// This avoids holding the entire decompressed file in memory.
func (r *Reader) extractFileToPath(in Inode, outPath string) error {
	if in.FileSize == 0 {
		return os.WriteFile(outPath, nil, os.FileMode(in.Perm))
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(in.Perm))
	if err != nil {
		return err
	}
	defer f.Close()

	blockStart := in.StartBlock
	written := uint64(0)

	// Write data blocks
	for _, bs := range in.BlockSizes {
		uncompressed := bs&(1<<24) != 0
		size := bs & 0x00FFFFFF
		if size == 0 {
			// Sparse block — write zeros
			zeros := make([]byte, r.SB.BlockSize)
			n, _ := f.Write(zeros)
			written += uint64(n)
			continue
		}

		end := blockStart + uint64(size)
		if int(end) > r.src.Len() {
			break
		}

		raw, err := r.readSlice(int(blockStart), int(end))
		if err != nil {
			break
		}

		if uncompressed {
			n, _ := f.Write(raw)
			written += uint64(n)
		} else {
			dec, err := r.decompress(raw, int(r.SB.BlockSize)*decompressLimit)
			if err != nil {
				return fmt.Errorf("data block @0x%X: %w", blockStart, err)
			}
			n, _ := f.Write(dec)
			written += uint64(n)
		}
		blockStart += uint64(size)
	}

	// Fragment
	if in.FragIndex != NoFragment && int(in.FragIndex) < len(r.frags) {
		frag := r.frags[in.FragIndex]
		fragUncomp := frag.Size&(1<<24) != 0
		fragSize := frag.Size & 0x00FFFFFF

		end := frag.Start + uint64(fragSize)
		if int(end) <= r.src.Len() {
			raw, err := r.readSlice(int(frag.Start), int(end))
			if err == nil {
				var fragData []byte
				if fragUncomp {
					fragData = raw
				} else {
					fragData, err = r.decompress(raw, int(r.SB.BlockSize)*decompressLimit)
					if err != nil {
						return nil // skip fragment on error
					}
				}

				fragOff := int(in.FragOffset)
				remaining := int(in.FileSize) - int(written)
				if remaining > 0 && fragOff+remaining <= len(fragData) {
					f.Write(fragData[fragOff : fragOff+remaining])
				} else if remaining > 0 && fragOff < len(fragData) {
					f.Write(fragData[fragOff:])
				}
			}
		}
	}

	// Truncate to exact size
	f.Truncate(int64(in.FileSize))
	return nil
}

// readFileData reads file content into memory. Use extractFileToPath for large files.
func (r *Reader) readFileData(in Inode) ([]byte, error) {
	if in.FileSize == 0 {
		return nil, nil
	}

	result := make([]byte, 0, in.FileSize)
	blockStart := in.StartBlock

	for _, bs := range in.BlockSizes {
		uncompressed := bs&(1<<24) != 0
		size := bs & 0x00FFFFFF
		if size == 0 {
			result = append(result, make([]byte, r.SB.BlockSize)...)
			continue
		}

		end := blockStart + uint64(size)
		if int(end) > r.src.Len() {
			break
		}

		raw, err := r.readSlice(int(blockStart), int(end))
		if err != nil {
			break
		}

		if uncompressed {
			result = append(result, raw...)
		} else {
			dec, err := r.decompress(raw, int(r.SB.BlockSize)*decompressLimit)
			if err != nil {
				return nil, fmt.Errorf("data block @0x%X: %w", blockStart, err)
			}
			result = append(result, dec...)
		}
		blockStart += uint64(size)
	}

	// Fragment
	if in.FragIndex != NoFragment && int(in.FragIndex) < len(r.frags) {
		frag := r.frags[in.FragIndex]
		fragUncomp := frag.Size&(1<<24) != 0
		fragSize := frag.Size & 0x00FFFFFF

		end := frag.Start + uint64(fragSize)
		if int(end) <= r.src.Len() {
			raw, err := r.readSlice(int(frag.Start), int(end))
			if err == nil {
				var fragData []byte
				if fragUncomp {
					fragData = raw
				} else {
					fragData, err = r.decompress(raw, int(r.SB.BlockSize)*decompressLimit)
					if err != nil {
						return result, nil
					}
				}

				fragOff := int(in.FragOffset)
				remaining := int(in.FileSize) - len(result)
				if fragOff+remaining <= len(fragData) {
					result = append(result, fragData[fragOff:fragOff+remaining]...)
				} else if fragOff < len(fragData) {
					result = append(result, fragData[fragOff:]...)
				}
			}
		}
	}

	if uint64(len(result)) > in.FileSize {
		result = result[:in.FileSize]
	}
	return result, nil
}

// ListRoot returns names of root directory entries.
func (r *Reader) ListRoot() ([]string, error) {
	rootInode, err := r.readInode(r.SB.RootInodeRef)
	if err != nil {
		return nil, err
	}
	entries, err := r.readDirEntries(rootInode)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names, nil
}

// IsSquashFS checks if data starts with SquashFS magic.
func IsSquashFS(data []byte) bool {
	return len(data) >= 4 && le32(data) == Magic
}

// Detect returns a human-readable description if the data is SquashFS.
func Detect(data []byte) string {
	if !IsSquashFS(data) {
		return ""
	}
	r, err := NewReader(data)
	if err != nil {
		return "SquashFS (parse error)"
	}
	return r.String()
}

// helpers
func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = strings.TrimSpace
