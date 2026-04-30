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
		zw := zlib.NewWriter(&buf)
		zw.Write(data)
		zw.Close()
	case CompXZ:
		compressed := XzCompress(data)
		buf.Write(compressed)
	case CompZstd:
		compressed := ZstdCompress(data, 3)
		// Validate roundtrip — pure-Go compressor can produce invalid output for some inputs
		if dec, err := ZstdDecompress(compressed); err != nil || len(dec) != len(data) {
			return data, true
		}
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
	isDev    bool
	target   string
	fileSize int64
	mode     uint32
	modTime  uint32
	uid      uint32
	gid      uint32
	devMajor uint32
	devMinor uint32
	children []*wNode
	parent   *wNode
	xattrs   map[string][]byte
	// Write state
	inodeNum   uint32
	inodeOff   int
	startBlock uint64
	blockSizes []uint32
	fragIdx    uint32
	fragOff    uint32
	uidIdx     uint16
	gidIdx     uint16
	// Dir info
	dirStart uint32
	dirSize  uint32
}

func (n *wNode) baseName() string {
	parts := strings.Split(n.relPath, "/")
	return parts[len(parts)-1]
}

// xattrEntry stores a key-value pair for the xattr table.
type xattrEntry struct {
	key   string
	value []byte
}

// CreateFromDir creates a SquashFS image from a directory (pure Go).
func (w *Writer) CreateFromDir(srcDir, outputPath string) error {
	// Phase 0: Build tree
	root := &wNode{path: srcDir, relPath: "", isDir: true, mode: 0755, modTime: uint32(time.Now().Unix())}
	// Get root stat for UID/GID
	if fi, err := os.Lstat(srcDir); err == nil {
		root.uid, root.gid = getStatUID(fi.Sys())
		root.mode = uint32(fi.Mode().Perm())
	}
	root.xattrs = readXattrs(srcDir)

	nodeMap := map[string]*wNode{"": root}
	inodeNum := uint32(1)
	root.inodeNum = inodeNum
	root.fragIdx = NoFragment

	var allNodes []*wNode
	allNodes = append(allNodes, root)

	// Collect unique UID/GID values
	idSet := map[uint32]bool{root.uid: true, root.gid: true}

	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == srcDir {
			return nil
		}
		rel, _ := filepath.Rel(srcDir, path)
		rel = filepath.ToSlash(rel)

		// Use Lstat to detect symlinks
		linfo, lerr := os.Lstat(path)
		if lerr != nil {
			return nil
		}

		node := &wNode{
			path:     path,
			relPath:  rel,
			isDir:    linfo.IsDir(),
			fileSize: linfo.Size(),
			mode:     uint32(linfo.Mode().Perm()),
			modTime:  uint32(linfo.ModTime().Unix()),
			fragIdx:  NoFragment,
		}

		// Get UID/GID from stat
		{ uid, gid := getStatUID(linfo.Sys())
			node.uid = uid
			node.gid = gid
			idSet[node.uid] = true
			idSet[node.gid] = true

			// Check for device nodes
			if linfo.Mode()&os.ModeDevice != 0 {
				node.isDev = true
				node.devMajor, node.devMinor = getDevMajorMinor(linfo.Sys())
				node.fileSize = 0
			}
		}

		if linfo.Mode()&os.ModeSymlink != 0 {
			node.isLink = true
			node.target, _ = os.Readlink(path)
			node.fileSize = 0
		}

		// Read xattrs
		node.xattrs = readXattrs(path)

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

	// Build sorted ID table
	var idList []uint32
	for id := range idSet {
		idList = append(idList, id)
	}
	sort.Slice(idList, func(i, j int) bool { return idList[i] < idList[j] })
	idIndex := map[uint32]uint16{}
	for i, id := range idList {
		idIndex[id] = uint16(i)
	}
	// Assign UID/GID indices
	for _, node := range allNodes {
		node.uidIdx = idIndex[node.uid]
		node.gidIdx = idIndex[node.gid]
	}

	// Sort children
	for _, n := range allNodes {
		sort.Slice(n.children, func(i, j int) bool {
			return n.children[i].baseName() < n.children[j].baseName()
		})
	}

	out := &bytes.Buffer{}
	out.Write(make([]byte, 96)) // superblock placeholder

	// Phase 1: Write data blocks + fragments with deduplication
	var fragBuf bytes.Buffer
	var fragEntries []fragEntry
	bs := int(w.BlockSize)

	// Fragment dedup: hash → fragIdx
	type fragRef struct {
		idx uint32
		off uint32
	}
	fragDedup := map[string]fragRef{}

	for _, node := range allNodes {
		if node.isDir || node.isLink || node.isDev || node.fileSize == 0 {
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
			fragData := data[fullBlocks*bs:]
			fragKey := string(fragData)

			if ref, ok := fragDedup[fragKey]; ok {
				// Reuse existing fragment
				node.fragIdx = ref.idx
				node.fragOff = ref.off
			} else {
				node.fragOff = uint32(fragBuf.Len())
				node.fragIdx = uint32(len(fragEntries))
				fragDedup[fragKey] = fragRef{idx: node.fragIdx, off: node.fragOff}
				fragBuf.Write(fragData)

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
					fragDedup = map[string]fragRef{} // reset dedup map for new fragment block
				}
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

	// Phase 2: Build xattr table
	// Collect all xattrs, assign indices
	type xattrRef struct {
		offset uint32 // byte offset into xattr value data
	}
	var xattrValueBuf bytes.Buffer
	var xattrIdTable []uint64 // offset into xattr metadata for each inode's xattr set
	nodeXattrIdx := map[uint32]uint32{} // inodeNum → xattr index

	hasXattrs := false
	for _, node := range allNodes {
		if len(node.xattrs) > 0 {
			hasXattrs = true
			break
		}
	}

	if hasXattrs {
		for _, node := range allNodes {
			if len(node.xattrs) == 0 {
				continue
			}
			nodeXattrIdx[node.inodeNum] = uint32(len(xattrIdTable))

			// Write key-value pairs
			offset := uint64(xattrValueBuf.Len())
			xattrIdTable = append(xattrIdTable, offset)

			// Sort keys for determinism
			var keys []string
			for k := range node.xattrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, k := range keys {
				v := node.xattrs[k]
				// Xattr entry: type(2) + name_size(2) + name + value_size(4) + value
				xattrType := xattrTypeFromKey(k)
				name := xattrStripPrefix(k)
				binary.Write(&xattrValueBuf, binary.LittleEndian, uint16(xattrType))
				binary.Write(&xattrValueBuf, binary.LittleEndian, uint16(len(name)))
				xattrValueBuf.WriteString(name)
				binary.Write(&xattrValueBuf, binary.LittleEndian, uint32(len(v)))
				xattrValueBuf.Write(v)
			}
		}
	}

	// Phase 3: Build directory table
	var dirBuf bytes.Buffer
	for _, node := range allNodes {
		if !node.isDir || len(node.children) == 0 {
			continue
		}
		node.dirStart = uint32(dirBuf.Len())

		binary.Write(&dirBuf, binary.LittleEndian, uint32(len(node.children)-1))
		binary.Write(&dirBuf, binary.LittleEndian, uint32(0))
		binary.Write(&dirBuf, binary.LittleEndian, node.children[0].inodeNum)

		for _, child := range node.children {
			binary.Write(&dirBuf, binary.LittleEndian, uint16(0)) // inode offset placeholder
			binary.Write(&dirBuf, binary.LittleEndian, int16(int32(child.inodeNum)-int32(node.children[0].inodeNum)))
			t := uint16(InodeBasicFile)
			if child.isDir {
				t = InodeBasicDir
			} else if child.isLink {
				t = InodeBasicSymlink
			} else if child.isDev {
				t = InodeBasicBlock
			}
			binary.Write(&dirBuf, binary.LittleEndian, t)
			name := child.baseName()
			binary.Write(&dirBuf, binary.LittleEndian, uint16(len(name)-1))
			dirBuf.WriteString(name)
		}
		node.dirSize = uint32(dirBuf.Len()) - node.dirStart
	}

	// Phase 4: Build inode table
	var inodeBuf bytes.Buffer
	var writeOrder func(n *wNode)
	writeOrder = func(n *wNode) {
		for _, child := range n.children {
			if child.isDir {
				writeOrder(child)
			} else {
				child.inodeOff = inodeBuf.Len()
				w.writeNodeInode(&inodeBuf, child)
			}
		}
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
		off := int(node.dirStart) + 12
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

	// Phase 5: Fragment table
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
		fragTableStart = uint64(out.Len())
		binary.Write(out, binary.LittleEndian, fragMetaStart)
	}

	// Phase 6: Xattr table
	xattrTableStart := uint64(0xFFFFFFFFFFFFFFFF)
	if hasXattrs && xattrValueBuf.Len() > 0 {
		xattrTableStart = uint64(out.Len())
		// Xattr table: metadata blocks containing key-value data
		xattrMetaStart := uint64(out.Len())
		w.writeMetablocks(out, xattrValueBuf.Bytes())

		// Xattr ID table: array of xattr_id entries (16 bytes each)
		// Then lookup table of uint64 pointers
		var idBuf bytes.Buffer
		for _, offset := range xattrIdTable {
			// xattr_id: xattr(8) + count(4) + size(4)
			binary.Write(&idBuf, binary.LittleEndian, offset)
			binary.Write(&idBuf, binary.LittleEndian, uint32(1)) // count
			binary.Write(&idBuf, binary.LittleEndian, uint32(0)) // size (unused by most implementations)
		}

		idMetaStart := uint64(out.Len())
		w.writeMetablocks(out, idBuf.Bytes())

		// Xattr table header: xattr_meta_start(8) + xattr_id_count(4) + padding(4)
		// Then lookup pointers
		xattrTableStart = uint64(out.Len())
		binary.Write(out, binary.LittleEndian, xattrMetaStart)
		binary.Write(out, binary.LittleEndian, uint32(len(xattrIdTable)))
		binary.Write(out, binary.LittleEndian, uint32(0)) // unused
		binary.Write(out, binary.LittleEndian, idMetaStart)
	}

	// Phase 7: ID table
	idData := make([]byte, len(idList)*4)
	for i, id := range idList {
		binary.LittleEndian.PutUint32(idData[i*4:], id)
	}
	idMetaStart := uint64(out.Len())
	w.writeMetablocks(out, idData)
	idTableStart := uint64(out.Len())
	binary.Write(out, binary.LittleEndian, idMetaStart)

	// Phase 8: Superblock
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
	binary.LittleEndian.PutUint16(sb[26:], uint16(len(idList)))
	binary.LittleEndian.PutUint16(sb[28:], 4) // v4.0
	binary.LittleEndian.PutUint16(sb[30:], 0)
	binary.LittleEndian.PutUint64(sb[32:], uint64(root.inodeOff)) // root inode ref
	binary.LittleEndian.PutUint64(sb[40:], totalBytes)
	binary.LittleEndian.PutUint64(sb[48:], idTableStart)
	binary.LittleEndian.PutUint64(sb[56:], xattrTableStart)
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
	} else if node.isDev {
		t = InodeBasicBlock
	}

	// Header: type(2) + perm(2) + uid_idx(2) + gid_idx(2) + mtime(4) + number(4)
	binary.Write(buf, binary.LittleEndian, t)
	binary.Write(buf, binary.LittleEndian, uint16(node.mode&0xFFF))
	binary.Write(buf, binary.LittleEndian, node.uidIdx)
	binary.Write(buf, binary.LittleEndian, node.gidIdx)
	binary.Write(buf, binary.LittleEndian, node.modTime)
	binary.Write(buf, binary.LittleEndian, node.inodeNum)

	switch {
	case node.isDev:
		// Basic device inode: nlinks(4) + rdev(4)
		binary.Write(buf, binary.LittleEndian, uint32(1)) // nlinks
		rdev := (node.devMajor << 8) | node.devMinor
		binary.Write(buf, binary.LittleEndian, rdev)

	case node.isDir:
		nlinks := uint32(len(node.children) + 2)
		parentNum := uint32(1)
		if node.parent != nil {
			parentNum = node.parent.inodeNum
		}
		binary.Write(buf, binary.LittleEndian, uint32(0))             // dir_start
		binary.Write(buf, binary.LittleEndian, nlinks)
		binary.Write(buf, binary.LittleEndian, uint16(node.dirSize))  // file_size - 3
		binary.Write(buf, binary.LittleEndian, uint16(node.dirStart)) // offset
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

// readXattrs reads extended attributes from a file path.

// xattrTypeFromKey returns the SquashFS xattr type prefix ID.
func xattrTypeFromKey(key string) uint16 {
	switch {
	case strings.HasPrefix(key, "user."):
		return 0
	case strings.HasPrefix(key, "trusted."):
		return 1
	case strings.HasPrefix(key, "security."):
		return 2
	default:
		return 0
	}
}

// xattrStripPrefix removes the known prefix from an xattr key.
func xattrStripPrefix(key string) string {
	for _, prefix := range []string{"user.", "trusted.", "security."} {
		if strings.HasPrefix(key, prefix) {
			return key[len(prefix):]
		}
	}
	return key
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
