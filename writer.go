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
	"strings"
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
	return &Writer{BlockSize: 131072, Compressor: CompGzip}
}

func (w *Writer) SetCompressor(comp uint16) *Writer { w.Compressor = comp; return w }

func (w *Writer) compress(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	switch w.Compressor {
	case CompGzip:
		gw := gzip.NewWriter(&buf)
		gw.Write(data)
		gw.Close()
	case CompXZ:
		xw, _ := xz.NewWriter(&buf)
		xw.Write(data)
		xw.Close()
	case CompZstd:
		zw, _ := zstd.NewWriter(&buf)
		zw.Write(data)
		zw.Close()
	default:
		return data, true
	}
	if buf.Len() >= len(data) {
		return data, true // uncompressed is smaller
	}
	return buf.Bytes(), false
}

type writerNode struct {
	path     string
	relPath  string
	isDir    bool
	isLink   bool
	target   string
	size     int64
	mode     uint32
	modTime  uint32
	children []*writerNode
	// assigned during write
	inodeNum   uint32
	startBlock uint64
	blockSizes []uint32
	fragIndex  uint32
	fragOffset uint32
}

// CreateFromDir creates a SquashFS image from a directory (pure Go).
func (w *Writer) CreateFromDir(srcDir, outputPath string) error {
	// Build file tree
	root := &writerNode{path: srcDir, relPath: "", isDir: true, mode: 0755, modTime: uint32(time.Now().Unix())}
	nodeMap := map[string]*writerNode{"": root}
	inodeNum := uint32(1)
	root.inodeNum = inodeNum

	var allNodes []*writerNode
	allNodes = append(allNodes, root)

	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == srcDir {
			return nil
		}
		rel, _ := filepath.Rel(srcDir, path)
		rel = filepath.ToSlash(rel)

		node := &writerNode{
			path:    path,
			relPath: rel,
			isDir:   info.IsDir(),
			size:    info.Size(),
			mode:    uint32(info.Mode().Perm()),
			modTime: uint32(info.ModTime().Unix()),
		}

		// Check symlink
		if info.Mode()&os.ModeSymlink != 0 {
			node.isLink = true
			node.target, _ = os.Readlink(path)
		}

		inodeNum++
		node.inodeNum = inodeNum
		node.fragIndex = NoFragment

		// Link to parent
		parentRel := filepath.ToSlash(filepath.Dir(rel))
		if parentRel == "." {
			parentRel = ""
		}
		if parent, ok := nodeMap[parentRel]; ok {
			parent.children = append(parent.children, node)
		}
		if node.isDir {
			nodeMap[rel] = node
		}
		allNodes = append(allNodes, node)
		return nil
	})

	// Sort children alphabetically (SquashFS requirement)
	for _, n := range allNodes {
		if n.isDir {
			sort.Slice(n.children, func(i, j int) bool {
				return n.children[i].baseName() < n.children[j].baseName()
			})
		}
	}

	// Create output
	out := &bytes.Buffer{}

	// Reserve superblock space
	out.Write(make([]byte, 96))

	// Phase 1: Write data blocks
	// Fragment accumulator
	var fragBuf bytes.Buffer
	var fragEntries []fragEntry
	fragBlockStart := uint64(0)

	for _, node := range allNodes {
		if node.isDir || node.isLink || node.size == 0 {
			continue
		}

		data, err := os.ReadFile(node.path)
		if err != nil {
			continue
		}

		node.startBlock = uint64(out.Len())
		bs := int(w.BlockSize)
		fullBlocks := len(data) / bs
		remainder := len(data) % bs

		// Write full blocks
		for i := 0; i < fullBlocks; i++ {
			block := data[i*bs : (i+1)*bs]
			compressed, isUncomp := w.compress(block)
			blockSize := uint32(len(compressed))
			if isUncomp {
				blockSize |= 1 << 24
			}
			node.blockSizes = append(node.blockSizes, blockSize)
			out.Write(compressed)
		}

		// Handle remainder (fragment)
		if remainder > 0 && fullBlocks > 0 {
			// Add to fragment
			node.fragOffset = uint32(fragBuf.Len())
			fragBuf.Write(data[fullBlocks*bs:])

			// Flush fragment if buffer is large enough
			if fragBuf.Len() >= bs {
				fragBlockStart = uint64(out.Len())
				compressed, isUncomp := w.compress(fragBuf.Bytes())
				fragSize := uint32(len(compressed))
				if isUncomp {
					fragSize |= 1 << 24
				}
				fragEntries = append(fragEntries, fragEntry{Start: fragBlockStart, Size: fragSize})
				out.Write(compressed)
				node.fragIndex = uint32(len(fragEntries) - 1)
				fragBuf.Reset()
			} else {
				node.fragIndex = uint32(len(fragEntries)) // will be current frag
			}
		} else if remainder > 0 && fullBlocks == 0 {
			// Small file: entire content in fragment
			node.fragOffset = uint32(fragBuf.Len())
			fragBuf.Write(data)
			node.fragIndex = uint32(len(fragEntries))

			if fragBuf.Len() >= bs {
				fragBlockStart = uint64(out.Len())
				compressed, isUncomp := w.compress(fragBuf.Bytes())
				fragSize := uint32(len(compressed))
				if isUncomp {
					fragSize |= 1 << 24
				}
				fragEntries = append(fragEntries, fragEntry{Start: fragBlockStart, Size: fragSize})
				out.Write(compressed)
				fragBuf.Reset()
			}
		} else {
			// No fragment needed (exact multiple of block size)
			node.fragIndex = NoFragment
		}
	}

	// Flush remaining fragments
	if fragBuf.Len() > 0 {
		fragBlockStart = uint64(out.Len())
		compressed, isUncomp := w.compress(fragBuf.Bytes())
		fragSize := uint32(len(compressed))
		if isUncomp {
			fragSize |= 1 << 24
		}
		fragEntries = append(fragEntries, fragEntry{Start: fragBlockStart, Size: fragSize})
		out.Write(compressed)
	}

	// Phase 2: Build inode table
	inodeTableStart := uint64(out.Len())
	var inodeTable bytes.Buffer
	inodeOffsets := make(map[uint32]uint64) // inodeNum → offset in inodeTable

	for _, node := range allNodes {
		inodeOffsets[node.inodeNum] = uint64(inodeTable.Len())
		w.writeInode(&inodeTable, node)
	}

	// Write inode table as metablocks
	w.writeMetablocks(out, inodeTable.Bytes())

	// Phase 3: Build directory table
	dirTableStart := uint64(out.Len())
	var dirTable bytes.Buffer
	dirOffsets := make(map[uint32][2]uint32) // inodeNum → [start, offset]

	for _, node := range allNodes {
		if !node.isDir || len(node.children) == 0 {
			continue
		}
		dirStart := uint32(dirTable.Len())
		// Write dir header
		count := uint32(len(node.children) - 1)
		binary.Write(&dirTable, binary.LittleEndian, count)
		// Start block (byte offset of first child's inode metablock)
		binary.Write(&dirTable, binary.LittleEndian, uint32(0)) // simplified
		binary.Write(&dirTable, binary.LittleEndian, node.children[0].inodeNum)

		for _, child := range node.children {
			// Entry: offset(2) + inode_delta(2) + type(2) + name_size(2) + name
			childOff := uint16(inodeOffsets[child.inodeNum] & 0xFFFF)
			binary.Write(&dirTable, binary.LittleEndian, childOff)
			binary.Write(&dirTable, binary.LittleEndian, int16(int32(child.inodeNum)-int32(node.children[0].inodeNum)))
			entType := uint16(InodeBasicFile)
			if child.isDir {
				entType = uint16(InodeBasicDir)
			} else if child.isLink {
				entType = uint16(InodeBasicSymlink)
			}
			binary.Write(&dirTable, binary.LittleEndian, entType)
			name := child.baseName()
			binary.Write(&dirTable, binary.LittleEndian, uint16(len(name)-1))
			dirTable.WriteString(name)
		}

		dirOffsets[node.inodeNum] = [2]uint32{dirStart, 0}
	}

	w.writeMetablocks(out, dirTable.Bytes())

	// Phase 4: Fragment table
	fragTableStart := uint64(out.Len())
	if len(fragEntries) > 0 {
		var fragData bytes.Buffer
		for _, fe := range fragEntries {
			binary.Write(&fragData, binary.LittleEndian, fe.Start)
			binary.Write(&fragData, binary.LittleEndian, fe.Size)
			binary.Write(&fragData, binary.LittleEndian, fe.Unused)
		}
		// Write as metablocks
		metaStart := uint64(out.Len())
		w.writeMetablocks(out, fragData.Bytes())

		// Write lookup table (pointer to metablock)
		binary.Write(out, binary.LittleEndian, metaStart)
		_ = metaStart
	}

	// Phase 5: ID table
	idTableStart := uint64(out.Len())
	// Write single ID (root:root = 0:0)
	idMeta := make([]byte, 4)
	binary.LittleEndian.PutUint32(idMeta, 0)
	metaStart := uint64(out.Len())
	w.writeMetablocks(out, idMeta)
	binary.Write(out, binary.LittleEndian, metaStart)

	// Phase 6: Update superblock
	totalBytes := uint64(out.Len())
	sb := out.Bytes()[:96]
	binary.LittleEndian.PutUint32(sb[0:], Magic)
	binary.LittleEndian.PutUint32(sb[4:], inodeNum)
	binary.LittleEndian.PutUint32(sb[8:], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(sb[12:], w.BlockSize)
	binary.LittleEndian.PutUint32(sb[16:], uint32(len(fragEntries)))
	binary.LittleEndian.PutUint16(sb[20:], w.Compressor)
	binary.LittleEndian.PutUint16(sb[22:], blockLog(w.BlockSize))
	binary.LittleEndian.PutUint16(sb[24:], 0x06C0) // flags
	binary.LittleEndian.PutUint16(sb[26:], 1)       // id count
	binary.LittleEndian.PutUint16(sb[28:], 4)       // version major
	binary.LittleEndian.PutUint16(sb[30:], 0)       // version minor
	binary.LittleEndian.PutUint64(sb[32:], 0)       // root inode ref (first inode)
	binary.LittleEndian.PutUint64(sb[40:], totalBytes)
	binary.LittleEndian.PutUint64(sb[48:], idTableStart)
	binary.LittleEndian.PutUint64(sb[56:], 0xFFFFFFFFFFFFFFFF) // no xattr
	binary.LittleEndian.PutUint64(sb[64:], inodeTableStart)
	binary.LittleEndian.PutUint64(sb[72:], dirTableStart)
	binary.LittleEndian.PutUint64(sb[80:], fragTableStart)
	binary.LittleEndian.PutUint64(sb[88:], 0xFFFFFFFFFFFFFFFF) // no lookup

	// Write to file
	return os.WriteFile(outputPath, out.Bytes(), 0644)
}

func (w *Writer) writeInode(buf *bytes.Buffer, node *writerNode) {
	// Common header: type(2) + perm(2) + uid(2) + gid(2) + mtime(4) + number(4)
	inodeType := uint16(InodeBasicFile)
	if node.isDir {
		inodeType = InodeBasicDir
	} else if node.isLink {
		inodeType = InodeBasicSymlink
	}

	binary.Write(buf, binary.LittleEndian, inodeType)
	binary.Write(buf, binary.LittleEndian, uint16(node.mode&0xFFF))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // uid idx
	binary.Write(buf, binary.LittleEndian, uint16(0)) // gid idx
	binary.Write(buf, binary.LittleEndian, node.modTime)
	binary.Write(buf, binary.LittleEndian, node.inodeNum)

	switch {
	case node.isDir:
		// BasicDir: start_block(4) + nlinks(4) + file_size(2) + offset(2) + parent(4)
		binary.Write(buf, binary.LittleEndian, uint32(0))              // dir start
		binary.Write(buf, binary.LittleEndian, uint32(len(node.children)+2)) // nlinks
		binary.Write(buf, binary.LittleEndian, uint16(0))              // dir size (placeholder)
		binary.Write(buf, binary.LittleEndian, uint16(0))              // offset
		binary.Write(buf, binary.LittleEndian, uint32(1))              // parent

	case node.isLink:
		// BasicSymlink: nlinks(4) + target_size(4) + target(N)
		binary.Write(buf, binary.LittleEndian, uint32(1))
		target := []byte(node.target)
		binary.Write(buf, binary.LittleEndian, uint32(len(target)))
		buf.Write(target)

	default:
		// BasicFile: start_block(4) + frag_index(4) + frag_offset(4) + file_size(4) + block_sizes(N*4)
		binary.Write(buf, binary.LittleEndian, uint32(node.startBlock))
		binary.Write(buf, binary.LittleEndian, node.fragIndex)
		binary.Write(buf, binary.LittleEndian, node.fragOffset)
		binary.Write(buf, binary.LittleEndian, uint32(node.size))
		for _, bs := range node.blockSizes {
			binary.Write(buf, binary.LittleEndian, bs)
		}
	}
}

func (w *Writer) writeMetablocks(out *bytes.Buffer, data []byte) {
	const metaBlockSize = 8192
	for off := 0; off < len(data); off += metaBlockSize {
		end := off + metaBlockSize
		if end > len(data) {
			end = len(data)
		}
		block := data[off:end]
		compressed, isUncomp := w.compress(block)

		header := uint16(len(compressed))
		if isUncomp {
			header |= 0x8000
		}
		binary.Write(out, binary.LittleEndian, header)
		out.Write(compressed)
	}
}

func (n *writerNode) baseName() string {
	parts := strings.Split(n.relPath, "/")
	return parts[len(parts)-1]
}

func blockLog(blockSize uint32) uint16 {
	log := uint16(0)
	for bs := blockSize; bs > 1; bs >>= 1 {
		log++
	}
	return log
}

// CreateWithMksquashfs creates a SquashFS image using external mksquashfs.
func CreateWithMksquashfs(srcDir, outputPath string, comp string) error {
	if comp == "" {
		comp = "gzip"
	}
	path, err := exec.LookPath("mksquashfs")
	if err != nil {
		return fmt.Errorf("mksquashfs not found: %w", err)
	}
	cmd := exec.Command(path, srcDir, outputPath, "-comp", comp, "-noappend", "-no-progress")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mksquashfs: %s: %w", string(output), err)
	}
	return nil
}

var _ = io.Copy
var _ = fmt.Sprintf
var _ = filepath.Join
