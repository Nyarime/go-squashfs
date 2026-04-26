package squashfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

)

type Writer struct {
	BlockSize  uint32
	Compressor uint16
}

func NewWriter() *Writer {
	return &Writer{BlockSize: 131072, Compressor: CompGzip}
}

func (w *Writer) SetCompressor(comp uint16) *Writer { w.Compressor = comp; return w }

func (w *Writer) compress(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	switch w.Compressor {
	case CompGzip:
		// SquashFS gzip = zlib (not gzip with headers)
		zw := zlib.NewWriter(&buf)
		zw.Write(data)
		zw.Close()
	case CompXZ:
		// XZ compression not yet self-implemented; return uncompressed
		return data, true
	case CompZstd:
		compressed := ZstdCompress(data, 3)
		buf.Write(compressed)
	default:
		return data, true
	}
	if buf.Len() >= len(data) {
		return data, true
	}
	return buf.Bytes(), false
}

type wNode struct {
	path     string
	relPath  string
	isDir    bool
	isLink   bool
	target   string
	fileSize int64
	mode     uint32
	modTime  uint32
	children []*wNode
	parent   *wNode
	// Write state
	inodeNum   uint32
	inodeOff   int    // byte offset in inode table (decompressed)
	startBlock uint64 // data block start in output
	blockSizes []uint32
	fragIdx    uint32
	fragOff    uint32
	// Dir info (set after dir table built)
	dirStart uint32 // byte offset in dir table (decompressed)
	dirSize  uint32
}

func (n *wNode) baseName() string {
	parts := strings.Split(n.relPath, "/")
	return parts[len(parts)-1]
}

// CreateFromDir creates a SquashFS image from a directory (pure Go).
func (w *Writer) CreateFromDir(srcDir, outputPath string) error {
	// Phase 0: Build tree
	root := &wNode{path: srcDir, relPath: "", isDir: true, mode: 0755, modTime: uint32(time.Now().Unix())}
	nodeMap := map[string]*wNode{"": root}
	inodeNum := uint32(1)
	root.inodeNum = inodeNum
	root.fragIdx = NoFragment

	var allNodes []*wNode
	allNodes = append(allNodes, root)

	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == srcDir {
			return nil
		}
		rel, _ := filepath.Rel(srcDir, path)
		rel = filepath.ToSlash(rel)

		node := &wNode{
			path:     path,
			relPath:  rel,
			isDir:    info.IsDir(),
			fileSize: info.Size(),
			mode:     uint32(info.Mode().Perm()),
			modTime:  uint32(info.ModTime().Unix()),
			fragIdx:  NoFragment,
		}

		if info.Mode()&os.ModeSymlink != 0 {
			node.isLink = true
			node.target, _ = os.Readlink(path)
			node.fileSize = 0
		}

		inodeNum++
		node.inodeNum = inodeNum

		parentRel := filepath.ToSlash(filepath.Dir(rel))
		if parentRel == "." {
			parentRel = ""
		}
		if parent, ok := nodeMap[parentRel]; ok {
			parent.children = append(parent.children, node)
			node.parent = parent
		}
		if node.isDir {
			nodeMap[rel] = node
		}
		allNodes = append(allNodes, node)
		return nil
	})

	// Sort children
	for _, n := range allNodes {
		sort.Slice(n.children, func(i, j int) bool {
			return n.children[i].baseName() < n.children[j].baseName()
		})
	}

	out := &bytes.Buffer{}
	out.Write(make([]byte, 96)) // superblock placeholder

	// Phase 1: Write data blocks + fragments
	var fragBuf bytes.Buffer
	var fragEntries []fragEntry
	bs := int(w.BlockSize)

	for _, node := range allNodes {
		if node.isDir || node.isLink || node.fileSize == 0 {
			continue
		}
		data, err := os.ReadFile(node.path)
		if err != nil {
			continue
		}

		node.startBlock = uint64(out.Len())
		fullBlocks := len(data) / bs
		remainder := len(data) % bs

		for i := 0; i < fullBlocks; i++ {
			block := data[i*bs : (i+1)*bs]
			comp, isUncomp := w.compress(block)
			bsVal := uint32(len(comp))
			if isUncomp {
				bsVal |= 1 << 24
			}
			node.blockSizes = append(node.blockSizes, bsVal)
			out.Write(comp)
		}

		if remainder > 0 {
			node.fragOff = uint32(fragBuf.Len())
			node.fragIdx = uint32(len(fragEntries))
			fragBuf.Write(data[fullBlocks*bs:])

			if fragBuf.Len() >= bs {
				fStart := uint64(out.Len())
				comp, isUncomp := w.compress(fragBuf.Bytes())
				fSize := uint32(len(comp))
				if isUncomp {
					fSize |= 1 << 24
				}
				fragEntries = append(fragEntries, fragEntry{Start: fStart, Size: fSize})
				out.Write(comp)
				fragBuf.Reset()
			}
		}
	}

	if fragBuf.Len() > 0 {
		fStart := uint64(out.Len())
		comp, isUncomp := w.compress(fragBuf.Bytes())
		fSize := uint32(len(comp))
		if isUncomp {
			fSize |= 1 << 24
		}
		fragEntries = append(fragEntries, fragEntry{Start: fStart, Size: fSize})
		out.Write(comp)
	}

	// Phase 2: Build directory table
	var dirBuf bytes.Buffer
	for _, node := range allNodes {
		if !node.isDir || len(node.children) == 0 {
			continue
		}
		node.dirStart = uint32(dirBuf.Len())

		binary.Write(&dirBuf, binary.LittleEndian, uint32(len(node.children)-1)) // count
		binary.Write(&dirBuf, binary.LittleEndian, uint32(0))                     // inode block (byte offset, set to 0 = first metablock)
		binary.Write(&dirBuf, binary.LittleEndian, node.children[0].inodeNum)     // base inode

		for _, child := range node.children {
			binary.Write(&dirBuf, binary.LittleEndian, uint16(0)) // inode offset (set in Phase 3)
			binary.Write(&dirBuf, binary.LittleEndian, int16(int32(child.inodeNum)-int32(node.children[0].inodeNum)))
			t := uint16(InodeBasicFile)
			if child.isDir {
				t = InodeBasicDir
			} else if child.isLink {
				t = InodeBasicSymlink
			}
			binary.Write(&dirBuf, binary.LittleEndian, t)
			name := child.baseName()
			binary.Write(&dirBuf, binary.LittleEndian, uint16(len(name)-1))
			dirBuf.WriteString(name)
		}
		node.dirSize = uint32(dirBuf.Len()) - node.dirStart
	}

	// Phase 3: Build inode table (depth-first: leaves before parents)
	var inodeBuf bytes.Buffer
	var writeOrder func(n *wNode)
	writeOrder = func(n *wNode) {
		// Write children first (sorted), then self
		for _, child := range n.children {
			if child.isDir {
				writeOrder(child)
			} else {
				child.inodeOff = inodeBuf.Len()
				w.writeNodeInode(&inodeBuf, child)
			}
		}
		// Write self (directory) after all children
		n.inodeOff = inodeBuf.Len()
		w.writeNodeInode(&inodeBuf, n)
	}
	writeOrder(root)

	// Patch dir entries with correct inode offsets
	dirBytes := dirBuf.Bytes()
	for _, node := range allNodes {
		if !node.isDir || len(node.children) == 0 {
			continue
		}
		off := int(node.dirStart) + 12 // skip header
		for _, child := range node.children {
			if off+2 <= len(dirBytes) {
				binary.LittleEndian.PutUint16(dirBytes[off:], uint16(child.inodeOff))
			}
			nameLen := int(binary.LittleEndian.Uint16(dirBytes[off+6:])) + 1
			off += 8 + nameLen
		}
	}

	// Write tables
	inodeTableStart := uint64(out.Len())
	w.writeMetablocks(out, inodeBuf.Bytes())

	dirTableStart := uint64(out.Len())
	w.writeMetablocks(out, dirBytes)

	// Phase 4: Fragment table
	fragTableStart := uint64(out.Len())
	if len(fragEntries) > 0 {
		var fragData bytes.Buffer
		for _, fe := range fragEntries {
			binary.Write(&fragData, binary.LittleEndian, fe.Start)
			binary.Write(&fragData, binary.LittleEndian, fe.Size)
			binary.Write(&fragData, binary.LittleEndian, fe.Unused)
		}
		fragMetaStart := uint64(out.Len())
		w.writeMetablocks(out, fragData.Bytes())
		fragTableStart = uint64(out.Len()) // lookup table
		binary.Write(out, binary.LittleEndian, fragMetaStart)
	}

	// Phase 5: ID table
	// Format: metablock(s) containing uint32 IDs, then lookup table of uint64 pointers
	idData := make([]byte, 4) // single ID = 0 (root)
	idMetaStart := uint64(out.Len())
	w.writeMetablocks(out, idData)
	idTableStart := uint64(out.Len()) // lookup table starts here
	binary.Write(out, binary.LittleEndian, idMetaStart) // pointer to metablock

	// Phase 6: Superblock
	totalBytes := uint64(out.Len())
	sb := out.Bytes()[:96]
	binary.LittleEndian.PutUint32(sb[0:], Magic)
	binary.LittleEndian.PutUint32(sb[4:], inodeNum)
	binary.LittleEndian.PutUint32(sb[8:], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(sb[12:], w.BlockSize)
	binary.LittleEndian.PutUint32(sb[16:], uint32(len(fragEntries)))
	binary.LittleEndian.PutUint16(sb[20:], w.Compressor)
	binary.LittleEndian.PutUint16(sb[22:], blockLog(w.BlockSize))
	binary.LittleEndian.PutUint16(sb[24:], 0x00C0) // flags: dedup + always_frag
	binary.LittleEndian.PutUint16(sb[26:], 1) // id count
	binary.LittleEndian.PutUint16(sb[28:], 4) // v4.0
	binary.LittleEndian.PutUint16(sb[30:], 0)
	binary.LittleEndian.PutUint64(sb[32:], uint64(root.inodeOff)) // root inode ref
	binary.LittleEndian.PutUint64(sb[40:], totalBytes)
	binary.LittleEndian.PutUint64(sb[48:], idTableStart)
	binary.LittleEndian.PutUint64(sb[56:], 0xFFFFFFFFFFFFFFFF)
	binary.LittleEndian.PutUint64(sb[64:], inodeTableStart)
	binary.LittleEndian.PutUint64(sb[72:], dirTableStart)
	binary.LittleEndian.PutUint64(sb[80:], fragTableStart)
	binary.LittleEndian.PutUint64(sb[88:], 0xFFFFFFFFFFFFFFFF)

	return os.WriteFile(outputPath, out.Bytes(), 0644)
}

func (w *Writer) writeNodeInode(buf *bytes.Buffer, node *wNode) {
	t := uint16(InodeBasicFile)
	if node.isDir {
		t = InodeBasicDir
	} else if node.isLink {
		t = InodeBasicSymlink
	}

	// Header: type(2) + perm(2) + uid(2) + gid(2) + mtime(4) + number(4)
	binary.Write(buf, binary.LittleEndian, t)
	binary.Write(buf, binary.LittleEndian, uint16(node.mode&0xFFF))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, node.modTime)
	binary.Write(buf, binary.LittleEndian, node.inodeNum)

	switch {
	case node.isDir:
		nlinks := uint32(len(node.children) + 2)
		parentNum := uint32(1)
		if node.parent != nil {
			parentNum = node.parent.inodeNum
		}
		// dir_start = compressed metablock offset from DirTableStart (0 for single metablock)
		// offset = decompressed byte offset within that metablock
		binary.Write(buf, binary.LittleEndian, uint32(0))            // dir_start (single metablock)
		binary.Write(buf, binary.LittleEndian, nlinks)
		binary.Write(buf, binary.LittleEndian, uint16(node.dirSize)) // file_size - 3
		binary.Write(buf, binary.LittleEndian, uint16(node.dirStart)) // offset within metablock
		binary.Write(buf, binary.LittleEndian, parentNum)

	case node.isLink:
		binary.Write(buf, binary.LittleEndian, uint32(1)) // nlinks
		target := []byte(node.target)
		binary.Write(buf, binary.LittleEndian, uint32(len(target)))
		buf.Write(target)

	default: // file
		binary.Write(buf, binary.LittleEndian, uint32(node.startBlock))
		binary.Write(buf, binary.LittleEndian, node.fragIdx)
		binary.Write(buf, binary.LittleEndian, node.fragOff)
		binary.Write(buf, binary.LittleEndian, uint32(node.fileSize))
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
		comp, isUncomp := w.compress(block)
		header := uint16(len(comp))
		if isUncomp {
			header |= 0x8000
		}
		binary.Write(out, binary.LittleEndian, header)
		out.Write(comp)
	}
}

func blockLog(blockSize uint32) uint16 {
	log := uint16(0)
	for bs := blockSize; bs > 1; bs >>= 1 {
		log++
	}
	return log
}

// CreateWithMksquashfs uses external mksquashfs (recommended for production).
func CreateWithMksquashfs(srcDir, outputPath string, comp string) error {
	if comp == "" {
		comp = "gzip"
	}
	p, err := exec.LookPath("mksquashfs")
	if err != nil {
		return fmt.Errorf("mksquashfs not found: %w", err)
	}
	cmd := exec.Command(p, srcDir, outputPath, "-comp", comp, "-noappend", "-no-progress")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mksquashfs: %s: %w", string(output), err)
	}
	return nil
}

var _ = io.Copy
var _ = fmt.Sprintf
