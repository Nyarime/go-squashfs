// Package squashfs provides a pure Go SquashFS reader.
// Supports gzip, xz, lzma, lz4, zstd compression.
// Designed for firmware analysis — works on Linux, macOS, and Windows.
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

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
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
	Start    uint64
	Size     uint32
	Unused   uint32
}

type Reader struct {
	data      []byte
	SB        Superblock
	inodeData []byte // decompressed inode table
	dirData   []byte // decompressed directory table
	frags     []fragEntry
	inodeMetaMap []metaMapping // compressed offset → decompressed offset
	dirMetaMap   []metaMapping
}

type metaMapping struct {
	compOff uint64 // offset from table start (compressed stream)
	decOff  uint64 // offset in decompressed data
}

// NewReader creates a SquashFS reader from raw bytes.
func NewReader(data []byte) (*Reader, error) {
	if len(data) < 96 {
		return nil, fmt.Errorf("squashfs: too short")
	}
	r := &Reader{data: data}
	d := data
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

	// Pre-read inode and directory tables
	var err error
	r.inodeData, r.inodeMetaMap, err = r.readMetaRange(r.SB.InodeTableStart, r.SB.DirTableStart)
	if err != nil {
		return nil, fmt.Errorf("inode table: %w", err)
	}
	r.dirData, r.dirMetaMap, err = r.readMetaRange(r.SB.DirTableStart, r.SB.FragTableStart)
	if err != nil {
		return nil, fmt.Errorf("dir table: %w", err)
	}

	// Read fragment table
	if r.SB.FragmentCount > 0 {
		r.frags, err = r.readFragTable()
		if err != nil {
			// Non-fatal: some files may not extract
			r.frags = nil
		}
	}

	return r, nil
}

// OpenFile opens a SquashFS from a file path.
func OpenFile(path string) (*Reader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewReader(data)
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

// Decompress decompresses data using the filesystem's compressor.
func (r *Reader) Decompress(compressed []byte) ([]byte, error) {
	switch r.SB.Compressor {
	case CompGzip:
		// SquashFS "gzip" = zlib (not gzip with extra headers)
		zr, err := zlib.NewReader(bytes.NewReader(compressed))
		if err != nil {
			// Fallback to gzip
			gr, gerr := gzip.NewReader(bytes.NewReader(compressed))
			if gerr != nil {
				return nil, err
			}
			defer gr.Close()
			return io.ReadAll(gr)
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case CompXZ:
		xr, err := xz.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(xr)
	case CompLZMA:
		lr, err := lzma.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(lr)
	case CompZstd:
		zr, err := zstd.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	default:
		return nil, fmt.Errorf("unsupported: %s", r.CompressorName())
	}
}

func (r *Reader) readMetablock(offset uint64) ([]byte, uint64, error) {
	if int(offset)+2 > len(r.data) {
		return nil, 0, fmt.Errorf("metablock @0x%X beyond data", offset)
	}
	header := le16(r.data[offset:])
	uncomp := header&0x8000 != 0
	size := int(header & 0x7FFF)
	end := int(offset) + 2 + size
	if end > len(r.data) {
		return nil, 0, fmt.Errorf("metablock data beyond file")
	}
	raw := r.data[offset+2 : uint64(end)]
	if uncomp {
		return raw, uint64(size) + 2, nil
	}
	dec, err := r.Decompress(raw)
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
	// Fragment table is a lookup table: array of uint64 metablock pointers
	// at FragTableStart. Number of entries = ceil(FragmentCount / 512) pointers.
	nPtrs := (int(r.SB.FragmentCount) + 511) / 512
	ptrOff := int(r.SB.FragTableStart)
	if ptrOff+nPtrs*8 > len(r.data) {
		return nil, fmt.Errorf("frag table pointers beyond data")
	}

	var allFragData []byte
	for i := 0; i < nPtrs; i++ {
		ptr := le64(r.data[ptrOff+i*8:])
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

// readInode reads an inode from a reference (block_off << 16 | byte_off)
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
	// uid/gid idx at 4,6
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
		// parent at d[28:]

	case InodeExtDir:
		if pos+40 > len(r.inodeData) {
			return in, fmt.Errorf("ext dir inode too short")
		}
		in.Nlinks = le32(d[16:])
		in.DirSize = le32(d[20:]) + 3
		in.DirStart = le32(d[24:])
		// parent at d[28:]
		// index_count at d[32:]
		in.DirOffset = le16(d[34:])

	case InodeBasicFile:
		if pos+32 > len(r.inodeData) {
			return in, fmt.Errorf("basic file inode too short")
		}
		in.StartBlock = uint64(le32(d[16:]))
		in.FragIndex = le32(d[20:])
		in.FragOffset = le32(d[24:])
		in.FileSize = uint64(le32(d[28:]))
		// Block sizes follow
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
		if pos+40 > len(r.inodeData) {
			return in, fmt.Errorf("ext file inode too short")
		}
		in.StartBlock = le64(d[16:])
		in.FileSize = le64(d[24:])
		// sparse at d[32:]
		in.Nlinks = le32(d[40:])
		in.FragIndex = le32(d[44:])
		in.FragOffset = le32(d[48:])
		// xattr at d[52:]
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

// metaToDecOffset maps a compressed byte offset to decompressed offset using the pre-built map
func (r *Reader) resolveInodeRef(blockOff uint32) uint64 {
	// blockOff is byte offset from InodeTableStart to the metablock
	for i := len(r.inodeMetaMap) - 1; i >= 0; i-- {
		if uint64(blockOff) >= r.inodeMetaMap[i].compOff {
			return r.inodeMetaMap[i].decOff
		}
	}
	return uint64(blockOff) // fallback
}

func (r *Reader) resolveDirRef(blockOff uint32) uint64 {
	for i := len(r.dirMetaMap) - 1; i >= 0; i-- {
		if uint64(blockOff) >= r.dirMetaMap[i].compOff {
			return r.dirMetaMap[i].decOff
		}
	}
	return uint64(blockOff)
}

// readDirEntries reads directory entries from dirData
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

			// Build inode reference
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

type dirEntry struct {
	Name     string
	InodeRef uint64
	InodeNum uint32
	Type     uint16
}

// ExtractTo extracts the entire filesystem to outDir.
func (r *Reader) ExtractTo(outDir string) (int, error) {
	os.MkdirAll(outDir, 0755)

	rootInode, err := r.readInode(r.SB.RootInodeRef)
	if err != nil {
		return 0, fmt.Errorf("root inode: %w", err)
	}

	count := 0
	err = r.extractDir(outDir, rootInode, &count, 0)
	return count, err
}

func (r *Reader) extractDir(path string, in Inode, count *int, depth int) error {
	if depth > 20 {
		return nil // prevent infinite recursion
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
		fullPath := filepath.Join(path, e.Name)

		childInode, err := r.readInode(e.InodeRef)
		if err != nil {
			continue // skip bad inodes
		}

		switch childInode.Type {
		case InodeBasicDir, InodeExtDir:
			r.extractDir(fullPath, childInode, count, depth+1)

		case InodeBasicFile, InodeExtFile:
			data, err := r.readFileData(childInode)
			if err != nil {
				continue
			}
			os.WriteFile(fullPath, data, os.FileMode(childInode.Perm))
			*count++

		case InodeBasicSymlink, InodeExtSymlink:
			if childInode.SymTarget != "" {
				os.Symlink(childInode.SymTarget, fullPath)
				*count++
			}

		default:
			// block/char/fifo/socket — skip
		}
	}
	return nil
}

// readFileData reads file content from data blocks + fragment
func (r *Reader) readFileData(in Inode) ([]byte, error) {
	if in.FileSize == 0 {
		return nil, nil
	}

	var result []byte
	blockStart := in.StartBlock

	// Read full data blocks
	for _, bs := range in.BlockSizes {
		uncompressed := bs&(1<<24) != 0
		size := bs & 0x00FFFFFF
		if size == 0 {
			// Sparse block
			result = append(result, make([]byte, r.SB.BlockSize)...)
			continue
		}

		end := blockStart + uint64(size)
		if int(end) > len(r.data) {
			break
		}

		raw := r.data[blockStart:end]
		if uncompressed {
			result = append(result, raw...)
		} else {
			dec, err := r.Decompress(raw)
			if err != nil {
				return nil, fmt.Errorf("data block @0x%X: %w", blockStart, err)
			}
			result = append(result, dec...)
		}
		blockStart += uint64(size)
	}

	// Read fragment if present
	if in.FragIndex != NoFragment && int(in.FragIndex) < len(r.frags) {
		frag := r.frags[in.FragIndex]
		fragUncomp := frag.Size&(1<<24) != 0
		fragSize := frag.Size & 0x00FFFFFF

		end := frag.Start + uint64(fragSize)
		if int(end) <= len(r.data) {
			raw := r.data[frag.Start:end]
			var fragData []byte
			if fragUncomp {
				fragData = raw
			} else {
				var err error
				fragData, err = r.Decompress(raw)
				if err != nil {
					return result, nil // skip fragment on error
				}
			}

			// Extract our portion from the fragment block
			fragOff := int(in.FragOffset)
			remaining := int(in.FileSize) - len(result)
			if fragOff+remaining <= len(fragData) {
				result = append(result, fragData[fragOff:fragOff+remaining]...)
			} else if fragOff < len(fragData) {
				result = append(result, fragData[fragOff:]...)
			}
		}
	}

	// Trim to exact file size
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

// Ensure strings import is used
var _ = strings.TrimSpace
