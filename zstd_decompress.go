package squashfs

// Pure Go Zstandard (RFC 8878) decompressor.
// Implements frame decoding, FSE/Huffman entropy decoding, and sequence execution.
// Only decompression — no compression support.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ──────────────────────────── public API ────────────────────────────

// ZstdDecompress decompresses a complete zstd frame (or concatenated frames).
func ZstdDecompress(src []byte) ([]byte, error) {
	var out []byte
	for len(src) > 0 {
		// skip skippable frames
		if len(src) >= 8 && src[0] >= 0x50 && src[0] <= 0x5F && src[1] == 0x2A && src[2] == 0x4D && src[3] == 0x18 {
			sz := int(binary.LittleEndian.Uint32(src[4:8]))
			src = src[8+sz:]
			continue
		}
		dec, rest, err := zstdDecodeFrame(src, out)
		if err != nil {
			return nil, err
		}
		out = dec
		src = rest
	}
	return out, nil
}

// ZstdNewReader creates a streaming zstd reader.
func ZstdNewReader(r io.Reader) (*ZstdReader, error) {
	return &ZstdReader{src: r}, nil
}

// ZstdReader is a streaming zstd decompressor.
type ZstdReader struct {
	src    io.Reader
	buf    []byte // decompressed but not yet consumed
	done   bool
	rawBuf []byte // raw input accumulator
}

// Read implements io.Reader.
func (z *ZstdReader) Read(p []byte) (int, error) {
	for len(z.buf) == 0 {
		if z.done {
			return 0, io.EOF
		}
		if err := z.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, z.buf)
	z.buf = z.buf[n:]
	return n, nil
}

// DecodeAll decompresses src appending to dst.
func (z *ZstdReader) DecodeAll(src, dst []byte) ([]byte, error) {
	out, err := ZstdDecompress(src)
	if err != nil {
		return dst, err
	}
	return append(dst, out...), nil
}

// Close releases resources.
func (z *ZstdReader) Close() {
	z.buf = nil
	z.rawBuf = nil
	z.done = true
}

func (z *ZstdReader) fill() error {
	// Read more raw data
	tmp := make([]byte, 64*1024)
	n, readErr := z.src.Read(tmp)
	if n > 0 {
		z.rawBuf = append(z.rawBuf, tmp[:n]...)
	}

	// Try to decode a frame
	if len(z.rawBuf) >= 4 {
		dec, rest, err := zstdDecodeFrame(z.rawBuf, nil)
		if err == nil {
			z.buf = dec
			z.rawBuf = rest
			return nil
		}
		// If we got a read error and still can't decode, that's terminal
		if readErr != nil {
			if readErr == io.EOF && len(z.rawBuf) == 0 {
				z.done = true
				return io.EOF
			}
			// Try one more time with what we have - maybe incomplete frame
			// Keep reading more data
			if errors.Is(readErr, io.EOF) {
				z.done = true
				if len(z.rawBuf) > 0 {
					// try to decompress what we have
					dec2, _, err2 := zstdDecodeFrame(z.rawBuf, nil)
					if err2 != nil {
						return fmt.Errorf("zstd: incomplete frame: %w", err2)
					}
					z.buf = dec2
					z.rawBuf = nil
					return nil
				}
				return io.EOF
			}
			return readErr
		}
	} else if readErr != nil {
		if readErr == io.EOF {
			z.done = true
			return io.EOF
		}
		return readErr
	}
	return nil
}

// ──────────────────────────── frame decoding ────────────────────────────

const zstdMagic = 0xFD2FB528

func zstdDecodeFrame(src []byte, dst []byte) ([]byte, []byte, error) {
	if len(src) < 4 {
		return nil, nil, fmt.Errorf("zstd: input too short")
	}
	magic := binary.LittleEndian.Uint32(src)
	if magic != zstdMagic {
		return nil, nil, fmt.Errorf("zstd: bad magic %#x", magic)
	}
	pos := 4

	// Frame_Header_Descriptor
	if pos >= len(src) {
		return nil, nil, fmt.Errorf("zstd: truncated frame header")
	}
	fhd := src[pos]
	pos++

	dictIDFlag := fhd & 3
	checksumFlag := (fhd >> 2) & 1
	_ = checksumFlag
	singleSegment := (fhd >> 5) & 1
	fcsField := (fhd >> 6) & 3

	// Window_Descriptor (absent if single segment)
	var windowSize uint64
	if singleSegment == 0 {
		if pos >= len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated window descriptor")
		}
		wd := src[pos]
		pos++
		exponent := uint(wd >> 3)
		mantissa := uint(wd & 7)
		windowLog := 10 + exponent
		windowBase := uint64(1) << windowLog
		windowAdd := (windowBase / 8) * uint64(mantissa)
		windowSize = windowBase + windowAdd
	}

	// Dictionary_ID
	var dictID uint32
	switch dictIDFlag {
	case 0: // no dict
	case 1:
		if pos >= len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated dict id")
		}
		dictID = uint32(src[pos])
		pos++
	case 2:
		if pos+2 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated dict id")
		}
		dictID = uint32(binary.LittleEndian.Uint16(src[pos:]))
		pos += 2
	case 3:
		if pos+4 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated dict id")
		}
		dictID = binary.LittleEndian.Uint32(src[pos:])
		pos += 4
	}
	_ = dictID

	// Frame_Content_Size
	var contentSize uint64
	var hasContentSize bool
	switch fcsField {
	case 0:
		if singleSegment == 1 {
			if pos >= len(src) {
				return nil, nil, fmt.Errorf("zstd: truncated fcs")
			}
			contentSize = uint64(src[pos])
			pos++
			hasContentSize = true
		}
	case 1:
		if pos+2 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated fcs")
		}
		contentSize = uint64(binary.LittleEndian.Uint16(src[pos:])) + 256
		pos += 2
		hasContentSize = true
	case 2:
		if pos+4 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated fcs")
		}
		contentSize = uint64(binary.LittleEndian.Uint32(src[pos:]))
		pos += 4
		hasContentSize = true
	case 3:
		if pos+8 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated fcs")
		}
		contentSize = binary.LittleEndian.Uint64(src[pos:])
		pos += 8
		hasContentSize = true
	}

	if singleSegment == 1 && hasContentSize {
		windowSize = contentSize
	}
	if windowSize == 0 {
		windowSize = 1 << 22 // default 4MB
	}
	_ = windowSize

	// Preallocate output
	if hasContentSize && contentSize < 128*1024*1024 {
		if dst == nil {
			dst = make([]byte, 0, contentSize)
		}
	} else if dst == nil {
		dst = make([]byte, 0, 64*1024)
	}

	// Decode blocks
	var lastBlock bool
	for !lastBlock {
		if pos+3 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated block header at offset %d", pos)
		}
		bh := uint32(src[pos]) | uint32(src[pos+1])<<8 | uint32(src[pos+2])<<16
		pos += 3
		lastBlock = (bh & 1) != 0
		blockType := (bh >> 1) & 3
		blockSize := int(bh >> 3)

		switch blockType {
		case 0: // Raw_Block
			if pos+blockSize > len(src) {
				return nil, nil, fmt.Errorf("zstd: raw block overrun")
			}
			dst = append(dst, src[pos:pos+blockSize]...)
			pos += blockSize

		case 1: // RLE_Block
			if pos >= len(src) {
				return nil, nil, fmt.Errorf("zstd: RLE block overrun")
			}
			b := src[pos]
			pos++
			for i := 0; i < blockSize; i++ {
				dst = append(dst, b)
			}

		case 2: // Compressed_Block
			if pos+blockSize > len(src) {
				return nil, nil, fmt.Errorf("zstd: compressed block overrun")
			}
			var err error
			dst, err = zstdDecodeCompressedBlock(src[pos:pos+blockSize], dst)
			if err != nil {
				return nil, nil, fmt.Errorf("zstd: compressed block: %w", err)
			}
			pos += blockSize

		case 3:
			return nil, nil, fmt.Errorf("zstd: reserved block type")
		}
	}

	// Content checksum (4 bytes if flag set)
	if checksumFlag == 1 {
		if pos+4 > len(src) {
			return nil, nil, fmt.Errorf("zstd: truncated checksum")
		}
		pos += 4 // skip verification
	}

	return dst, src[pos:], nil
}

// ──────────────────────────── compressed block ────────────────────────────

func zstdDecodeCompressedBlock(block []byte, dst []byte) ([]byte, error) {
	if len(block) < 1 {
		return nil, fmt.Errorf("empty compressed block")
	}

	// Literals section
	literals, litEnd, err := zstdDecodeLiterals(block)
	if err != nil {
		return nil, fmt.Errorf("literals: %w", err)
	}

	// Sequences section
	seqData := block[litEnd:]
	dst, err = zstdDecodeSequences(seqData, literals, dst)
	if err != nil {
		return nil, fmt.Errorf("sequences: %w", err)
	}

	return dst, nil
}

// ──────────────────────────── literals section ────────────────────────────

func zstdDecodeLiterals(block []byte) ([]byte, int, error) {
	if len(block) < 1 {
		return nil, 0, fmt.Errorf("empty literals section")
	}

	litType := block[0] & 3
	sizeFormat := (block[0] >> 2) & 3

	switch litType {
	case 0: // Raw_Literals_Block
		return zstdDecodeRawLiterals(block, sizeFormat)
	case 1: // RLE_Literals_Block
		return zstdDecodeRLELiterals(block, sizeFormat)
	case 2: // Compressed_Literals_Block
		return zstdDecodeCompressedLiterals(block, sizeFormat, false)
	case 3: // Treeless_Literals_Block
		return zstdDecodeCompressedLiterals(block, sizeFormat, true)
	}
	return nil, 0, fmt.Errorf("unknown literal type %d", litType)
}

func zstdDecodeRawLiterals(block []byte, sizeFormat byte) ([]byte, int, error) {
	var regeneratedSize int
	var headerSize int
	switch sizeFormat {
	case 0, 2:
		regeneratedSize = int(block[0]) >> 3
		headerSize = 1
	case 1:
		if len(block) < 2 {
			return nil, 0, fmt.Errorf("truncated raw lit header")
		}
		regeneratedSize = (int(block[0]) >> 4) | (int(block[1]) << 4)
		headerSize = 2
	case 3:
		if len(block) < 3 {
			return nil, 0, fmt.Errorf("truncated raw lit header")
		}
		regeneratedSize = (int(block[0]) >> 4) | (int(block[1]) << 4) | (int(block[2]) << 12)
		headerSize = 3
	}
	end := headerSize + regeneratedSize
	if end > len(block) {
		return nil, 0, fmt.Errorf("raw literals overrun: need %d have %d", end, len(block))
	}
	return append([]byte(nil), block[headerSize:end]...), end, nil
}

func zstdDecodeRLELiterals(block []byte, sizeFormat byte) ([]byte, int, error) {
	var regeneratedSize int
	var headerSize int
	switch sizeFormat {
	case 0, 2:
		regeneratedSize = int(block[0]) >> 3
		headerSize = 1
	case 1:
		if len(block) < 2 {
			return nil, 0, fmt.Errorf("truncated RLE lit header")
		}
		regeneratedSize = (int(block[0]) >> 4) | (int(block[1]) << 4)
		headerSize = 2
	case 3:
		if len(block) < 3 {
			return nil, 0, fmt.Errorf("truncated RLE lit header")
		}
		regeneratedSize = (int(block[0]) >> 4) | (int(block[1]) << 4) | (int(block[2]) << 12)
		headerSize = 3
	}
	if headerSize >= len(block) {
		return nil, 0, fmt.Errorf("RLE literal missing byte")
	}
	b := block[headerSize]
	out := make([]byte, regeneratedSize)
	for i := range out {
		out[i] = b
	}
	return out, headerSize + 1, nil
}

func zstdDecodeCompressedLiterals(block []byte, sizeFormat byte, treeless bool) ([]byte, int, error) {
	_ = treeless // treeless reuses previous Huffman tree — not yet supported, will error if encountered with no prior tree

	var regeneratedSize, compressedSize int
	var headerSize int
	var numStreams int

	switch sizeFormat {
	case 0:
		// Both sizes use 10 bits; sizeFormat 0 => single stream
		if len(block) < 3 {
			return nil, 0, fmt.Errorf("truncated compressed lit header")
		}
		val := uint32(block[0])>>4 | uint32(block[1])<<4 | uint32(block[2])<<12
		regeneratedSize = int(val & 0x3FF)
		compressedSize = int((val >> 10) & 0x3FF)
		headerSize = 3
		numStreams = 1
	case 1:
		// Both sizes use 10 bits; sizeFormat 1 => 4 streams
		if len(block) < 3 {
			return nil, 0, fmt.Errorf("truncated compressed lit header")
		}
		val := uint32(block[0])>>4 | uint32(block[1])<<4 | uint32(block[2])<<12
		regeneratedSize = int(val & 0x3FF)
		compressedSize = int((val >> 10) & 0x3FF)
		headerSize = 3
		numStreams = 4
	case 2:
		if len(block) < 4 {
			return nil, 0, fmt.Errorf("truncated compressed lit header")
		}
		val := uint32(block[0])>>4 | uint32(block[1])<<4 | uint32(block[2])<<12 | uint32(block[3])<<20
		regeneratedSize = int(val & 0x3FFF)
		compressedSize = int((val >> 14) & 0x3FF)
		headerSize = 4
		numStreams = 4
	case 3:
		if len(block) < 5 {
			return nil, 0, fmt.Errorf("truncated compressed lit header")
		}
		val := uint64(block[0])>>4 | uint64(block[1])<<4 | uint64(block[2])<<12 | uint64(block[3])<<20 | uint64(block[4])<<28
		regeneratedSize = int(val & 0x3FFFF)
		compressedSize = int((val >> 18) & 0x3FFFF)
		headerSize = 5
		numStreams = 4
	}

	if headerSize+compressedSize > len(block) {
		return nil, 0, fmt.Errorf("compressed literals overrun: header %d + compressed %d > %d", headerSize, compressedSize, len(block))
	}

	compData := block[headerSize : headerSize+compressedSize]

	// Decode Huffman tree
	tree, treeSize, err := zstdDecodeHuffmanTree(compData)
	if err != nil {
		return nil, 0, fmt.Errorf("huffman tree: %w", err)
	}

	streamData := compData[treeSize:]

	var literals []byte
	if numStreams == 1 {
		literals, err = zstdHuffmanDecompress1Stream(tree, streamData, regeneratedSize)
	} else {
		literals, err = zstdHuffmanDecompress4Streams(tree, streamData, regeneratedSize)
	}
	if err != nil {
		return nil, 0, err
	}

	return literals, headerSize + compressedSize, nil
}

// ──────────────────────────── Huffman decoding ────────────────────────────

type zstdHuffmanTable struct {
	symbols  [2048]byte // lookup table: symbol for each state
	bits     [2048]byte // number of bits for each state
	maxBits  int
	numSyms  int
}

func zstdDecodeHuffmanTree(data []byte) (*zstdHuffmanTable, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("empty huffman header")
	}

	headerByte := data[0]
	var weights []byte
	var consumed int

	if headerByte < 128 {
		// FSE-compressed weights
		compSize := int(headerByte)
		if 1+compSize > len(data) {
			return nil, 0, fmt.Errorf("huffman weights overrun")
		}
		var err error
		weights, err = zstdDecodeFSEWeights(data[1:1+compSize])
		if err != nil {
			return nil, 0, err
		}
		consumed = 1 + compSize
	} else {
		// Direct representation
		numWeights := int(headerByte) - 127
		needed := (numWeights + 1) / 2
		if 1+needed > len(data) {
			return nil, 0, fmt.Errorf("huffman direct weights overrun")
		}
		weights = make([]byte, numWeights)
		for i := 0; i < numWeights; i++ {
			if i%2 == 0 {
				weights[i] = data[1+i/2] >> 4
			} else {
				weights[i] = data[1+i/2] & 0xF
			}
		}
		consumed = 1 + needed
	}

	tbl, _, err := zstdBuildHuffmanTable(weights)
	if err != nil {
		return nil, 0, err
	}
	return tbl, consumed, nil
}

func zstdBuildHuffmanTable(weights []byte) (*zstdHuffmanTable, int, error) {
	if len(weights) == 0 {
		return nil, 0, fmt.Errorf("no huffman weights")
	}

	numSymbols := len(weights) + 1

	// Find max weight
	var maxW byte
	var weightSum uint32
	for _, w := range weights {
		if w > maxW {
			maxW = w
		}
		if w > 0 {
			weightSum += 1 << (w - 1)
		}
	}

	// Last symbol weight: find smallest power of 2 >= weightSum, then last weight
	// Sum of (1 << (w-1)) for all w>0 + (1 << (lastW-1)) = 1 << maxBits
	// So lastWeight satisfies 1 << maxBits = weightSum + 1 << (lastWeight-1)
	// maxBits = highest bit of weightSum rounded up to next pow2

	// Calculate maxBits: ceil(log2(weightSum+1))
	maxBits := 0
	{
		target := weightSum
		for (uint32(1) << uint(maxBits)) <= target {
			maxBits++
		}
	}
	totalWeight := uint32(1) << uint(maxBits)
	remainder := totalWeight - weightSum
	// remainder must be a power of 2
	if remainder == 0 || (remainder&(remainder-1)) != 0 {
		return nil, 0, fmt.Errorf("invalid huffman weights (remainder %d not pow2, sum=%d, total=%d)", remainder, weightSum, totalWeight)
	}

	// Last symbol number of bits = maxBits + 1 - lastWeight
	lastWeight := byte(0)
	for i := byte(1); i <= byte(maxBits)+1; i++ {
		if uint32(1)<<(i-1) == remainder {
			lastWeight = i
			break
		}
	}

	allWeights := make([]byte, numSymbols)
	copy(allWeights, weights)
	allWeights[numSymbols-1] = lastWeight

	// Build table: symbol s with weight w gets code length = maxBits + 1 - w
	tbl := &zstdHuffmanTable{maxBits: maxBits, numSyms: numSymbols}

	// Count symbols per weight
	type symInfo struct {
		sym    byte
		nbBits int
	}
	var syms []symInfo
	for i, w := range allWeights {
		if w > 0 {
			syms = append(syms, symInfo{byte(i), maxBits + 1 - int(w)})
		}
	}

	// Sort by nbBits then by symbol
	for i := 1; i < len(syms); i++ {
		for j := i; j > 0; j-- {
			if syms[j].nbBits < syms[j-1].nbBits || (syms[j].nbBits == syms[j-1].nbBits && syms[j].sym < syms[j-1].sym) {
				syms[j], syms[j-1] = syms[j-1], syms[j]
			} else {
				break
			}
		}
	}

	// Build lookup: iterate over all symbols and assign consecutive codes at each bit length
	tableSize := 1 << uint(maxBits)
	if tableSize > len(tbl.symbols) {
		return nil, 0, fmt.Errorf("huffman table too large (%d)", tableSize)
	}

	code := 0
	prevBits := 0
	for _, s := range syms {
		if s.nbBits > prevBits {
			code <<= uint(s.nbBits - prevBits)
			prevBits = s.nbBits
		}
		// Fill table entries: each entry for this symbol fills 1<<(maxBits-nbBits) slots
		step := 1 << uint(maxBits-s.nbBits)
		base := zstdBitReverse(uint32(code), s.nbBits) // reverse bits for table lookup
		for j := int(base); j < tableSize; j += (1 << uint(s.nbBits)) {
			tbl.symbols[j] = s.sym
			tbl.bits[j] = byte(s.nbBits)
		}
		_ = step
		code++
	}

	return tbl, 0, nil // consumed already handled by caller
}

func zstdBitReverse(v uint32, nbBits int) uint32 {
	var r uint32
	for i := 0; i < nbBits; i++ {
		r = (r << 1) | (v & 1)
		v >>= 1
	}
	return r
}

func zstdHuffmanDecompress1Stream(tbl *zstdHuffmanTable, data []byte, outSize int) ([]byte, error) {
	br := newZstdBitReaderReverse(data)
	out := make([]byte, 0, outSize)

	// Initialize: find the leading 1 bit
	if err := br.initReverse(); err != nil {
		return nil, err
	}

	for len(out) < outSize {
		if br.bitsLeft() < 0 {
			return nil, fmt.Errorf("huffman: ran out of bits at %d/%d", len(out), outSize)
		}
		val := br.peekBits(tbl.maxBits)
		sym := tbl.symbols[val]
		nb := int(tbl.bits[val])
		if nb == 0 {
			return nil, fmt.Errorf("huffman: zero-bit symbol at position %d", len(out))
		}
		br.skipBits(nb)
		out = append(out, sym)
	}

	return out, nil
}

func zstdHuffmanDecompress4Streams(tbl *zstdHuffmanTable, data []byte, totalSize int) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("huffman 4-stream: not enough jump table data")
	}

	// 3 x 2-byte jump table entries (little-endian) specifying cumulative sizes of first 3 streams
	s1 := int(binary.LittleEndian.Uint16(data[0:2]))
	s2 := int(binary.LittleEndian.Uint16(data[2:4]))
	s3 := int(binary.LittleEndian.Uint16(data[4:6]))
	streams := data[6:]

	if s1 > len(streams) || s2 > len(streams) || s3 > len(streams) {
		return nil, fmt.Errorf("huffman 4-stream: jump table out of range")
	}

	seg := [4][]byte{
		streams[:s1],
		streams[s1:s2],
		streams[s2:s3],
		streams[s3:],
	}

	// Each stream decompresses to ~totalSize/4 (last one gets remainder)
	base := totalSize / 4
	sizes := [4]int{base, base, base, totalSize - 3*base}

	out := make([]byte, 0, totalSize)
	for i := 0; i < 4; i++ {
		part, err := zstdHuffmanDecompress1Stream(tbl, seg[i], sizes[i])
		if err != nil {
			return nil, fmt.Errorf("huffman stream %d: %w", i, err)
		}
		out = append(out, part...)
	}

	return out, nil
}

// ──────────────────────────── FSE (Finite State Entropy) ────────────────────────────

type zstdFSETable struct {
	symbols    []byte
	numBits    []byte
	newState   []uint16
	stateCount int
	accuracyLog int
}

// Decode FSE-compressed Huffman weights
func zstdDecodeFSEWeights(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty FSE data for weights")
	}

	table, headerSize, err := zstdBuildFSETableFromHeader(data, 6) // maxLog=6 for Huffman weights
	if err != nil {
		return nil, err
	}

	br := newZstdBitReaderReverse(data[headerSize:])
	if err := br.initReverse(); err != nil {
		return nil, err
	}

	// Initialize state
	state := br.readBits(table.accuracyLog)

	var weights []byte
	for br.bitsLeft() >= 0 && len(weights) < 256 {
		sym := table.symbols[state]
		nb := int(table.numBits[state])
		weights = append(weights, sym)

		if br.bitsLeft() < 0 {
			break
		}
		bits := br.readBits(nb)
		state = int(table.newState[state]) + bits
		if state >= table.stateCount {
			break
		}
	}

	return weights, nil
}

func zstdBuildFSETableFromHeader(data []byte, maxLog int) (*zstdFSETable, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("empty FSE header")
	}

	br := &zstdBitReaderForward{data: data}

	accuracyLog := int(br.readFwd(4)) + 5
	if accuracyLog > maxLog {
		return nil, 0, fmt.Errorf("FSE accuracy log %d exceeds max %d", accuracyLog, maxLog)
	}

	tableSize := 1 << uint(accuracyLog)
	remaining := tableSize + 1
	threshold := tableSize
	nbBits := accuracyLog + 1

	var probs []int16
	symbol := 0

	for remaining > 1 && symbol < 256 {
		if nbBits > 1 && threshold > 0 {
			// Read nbBits-1 bits
			lowBits := int(br.readFwd(nbBits - 1))
			mask := (1 << uint(nbBits)) - 1
			upperBound := mask - threshold + 1

			var prob int
			if lowBits < upperBound {
				prob = lowBits
			} else {
				extra := int(br.readFwd(1))
				prob = (lowBits << 1) + extra - upperBound
			}

			// prob == 0 means -1 (symbol present but probability < 1)
			// otherwise probability = prob - 1
			if prob == 0 {
				probs = append(probs, -1)
			} else {
				probVal := int16(prob - 1)
				probs = append(probs, probVal)
				remaining -= int(probVal)
			}
		} else {
			probs = append(probs, int16(remaining-1))
			remaining = 1
		}
		symbol++

		// Check for repeat zeros
		if probs[len(probs)-1] == 0 {
			// Repeat 0s - read 2 bits for repeat count
			for {
				rep := int(br.readFwd(2))
				for i := 0; i < rep; i++ {
					probs = append(probs, 0)
					symbol++
				}
				if rep < 3 {
					break
				}
			}
		}

		// Recalculate threshold/nbBits
		for remaining < threshold {
			threshold >>= 1
			nbBits--
		}
	}

	consumed := (br.bitPos + 7) / 8

	// Build decoding table
	table := &zstdFSETable{
		symbols:    make([]byte, tableSize),
		numBits:    make([]byte, tableSize),
		newState:   make([]uint16, tableSize),
		stateCount: tableSize,
		accuracyLog: accuracyLog,
	}

	// Step 1: place symbols with prob == -1 at the end
	highThreshold := tableSize - 1
	for sym, p := range probs {
		if p == -1 {
			table.symbols[highThreshold] = byte(sym)
			highThreshold--
		}
	}

	// Step 2: spread remaining symbols
	step := (tableSize >> 1) + (tableSize >> 3) + 3
	mask := tableSize - 1
	pos := 0
	for sym, p := range probs {
		if p <= 0 {
			continue
		}
		for i := int16(0); i < p; i++ {
			table.symbols[pos] = byte(sym)
			pos = (pos + step) & mask
			for pos > highThreshold {
				pos = (pos + step) & mask
			}
		}
	}

	// Step 3: build numBits and newState
	// For each symbol, track next available position
	symNext := make([]uint16, len(probs))
	for sym, p := range probs {
		if p == -1 {
			symNext[sym] = 1
		} else if p > 0 {
			symNext[sym] = uint16(p)
		}
	}

	for i := 0; i < tableSize; i++ {
		sym := table.symbols[i]
		nb := byte(accuracyLog) - zstdHighBit(uint32(symNext[sym]))
		table.numBits[i] = nb
		table.newState[i] = (symNext[sym] << nb) - uint16(tableSize)
		symNext[sym]++
	}

	return table, consumed, nil
}

func zstdHighBit(v uint32) byte {
	if v == 0 {
		return 0
	}
	n := byte(0)
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

// ──────────────────────────── Sequence decoding ────────────────────────────

type zstdSequence struct {
	litLen   int
	offset   int
	matchLen int
}

func zstdDecodeSequences(data []byte, literals []byte, dst []byte) ([]byte, error) {
	if len(data) == 0 {
		// No sequences — just append literals
		return append(dst, literals...), nil
	}

	// Number of sequences
	nbSeq := int(data[0])
	pos := 1
	if nbSeq == 0 {
		return append(dst, literals...), nil
	} else if nbSeq == 255 {
		if pos+1 >= len(data) {
			return nil, fmt.Errorf("truncated sequence count")
		}
		nbSeq = int(data[pos]) + (int(data[pos+1]) << 8) + 0x7F00
		pos += 2
	} else if nbSeq > 127 {
		if pos >= len(data) {
			return nil, fmt.Errorf("truncated sequence count")
		}
		nbSeq = ((nbSeq - 128) << 8) + int(data[pos])
		pos++
	}

	if pos >= len(data) {
		return nil, fmt.Errorf("truncated symbol compression modes")
	}

	// Symbol compression modes
	modes := data[pos]
	pos++
	llMode := (modes >> 6) & 3
	ofMode := (modes >> 4) & 3
	mlMode := (modes >> 2) & 3


	// Build FSE tables for LL, OF, ML
	streamData := data[pos:]
	streamPos := 0

	llTable, err := zstdGetSeqTable(llMode, streamData, &streamPos, zstdLLDefaultProbs, 9, 35)
	if err != nil {
		return nil, fmt.Errorf("LL table: %w", err)
	}
	ofTable, err := zstdGetSeqTable(ofMode, streamData, &streamPos, zstdOFDefaultProbs, 8, 28)
	if err != nil {
		return nil, fmt.Errorf("OF table: %w", err)
	}
	mlTable, err := zstdGetSeqTable(mlMode, streamData, &streamPos, zstdMLDefaultProbs, 9, 52)
	if err != nil {
		return nil, fmt.Errorf("ML table: %w", err)
	}

	// Bit reader from end of stream
	br := newZstdBitReaderReverse(streamData[streamPos:])
	if err := br.initReverse(); err != nil {
		return nil, fmt.Errorf("seq bitstream: %w", err)
	}

	// Initialize states
	llState := br.readBits(llTable.accuracyLog)
	ofState := br.readBits(ofTable.accuracyLog)
	mlState := br.readBits(mlTable.accuracyLog)

	// Decode sequences
	seqs := make([]zstdSequence, nbSeq)
	offsets := [3]int{1, 4, 8} // repeated offsets

	for i := 0; i < nbSeq; i++ {
		// Read the values
		ofCode := int(ofTable.symbols[ofState])
		llCode := int(llTable.symbols[llState])
		mlCode := int(mlTable.symbols[mlState])

		// Extra bits order per RFC 8878 §3.1.2.2: Offset, MatchLength, LiteralLength
		// Offset
		ofBits := ofCode
		var offset int
		if ofBits > 0 {
			offset = (1 << uint(ofBits)) + br.readBits(ofBits)
		} else {
			offset = 1
		}

		// Match length
		mlBits := zstdMLBits[mlCode]
		matchLen := zstdMLBaseline[mlCode] + br.readBits(mlBits)

		// Literal length
		llBits := zstdLLBits[llCode]
		litLen := zstdLLBaseline[llCode] + br.readBits(llBits)

		// Handle repeated offsets per RFC 8878 §3.1.2.5
		if offset <= 3 {
			var actualOffset int
			if litLen > 0 {
				// offset 1,2,3 => offsets[0], offsets[1], offsets[2]
				actualOffset = offsets[offset-1]
				if offset > 1 {
					if offset == 2 {
						offsets[1] = offsets[0]
					} else { // offset == 3
						offsets[2] = offsets[1]
						offsets[1] = offsets[0]
					}
					offsets[0] = actualOffset
				}
			} else {
				// litLen == 0: special rules
				switch offset {
				case 1:
					actualOffset = offsets[1]
					offsets[1] = offsets[0]
					offsets[0] = actualOffset
				case 2:
					actualOffset = offsets[2]
					offsets[2] = offsets[1]
					offsets[1] = offsets[0]
					offsets[0] = actualOffset
				case 3:
					actualOffset = offsets[0] - 1
					if actualOffset <= 0 {
						actualOffset = 1
					}
					offsets[2] = offsets[1]
					offsets[1] = offsets[0]
					offsets[0] = actualOffset
				}
			}
			offset = actualOffset
		} else {
			offset -= 3
			offsets[2] = offsets[1]
			offsets[1] = offsets[0]
			offsets[0] = offset
		}

		seqs[i] = zstdSequence{litLen: litLen, offset: offset, matchLen: matchLen}

		// Update states (not for last sequence)
		if i < nbSeq-1 {
			llBitsN := int(llTable.numBits[llState])
			llState = int(llTable.newState[llState]) + br.readBits(llBitsN)

			mlBitsN := int(mlTable.numBits[mlState])
			mlState = int(mlTable.newState[mlState]) + br.readBits(mlBitsN)

			ofBitsN := int(ofTable.numBits[ofState])
			ofState = int(ofTable.newState[ofState]) + br.readBits(ofBitsN)
		}
	}

	// Execute sequences
	litPos := 0
	for _, seq := range seqs {
		// Copy literals
		if seq.litLen > 0 {
			end := litPos + seq.litLen
			if end > len(literals) {
				return nil, fmt.Errorf("literal overrun: need %d, have %d", end, len(literals))
			}
			dst = append(dst, literals[litPos:end]...)
			litPos = end
		}

		// Copy match
		if seq.matchLen > 0 {
			matchStart := len(dst) - seq.offset
			if matchStart < 0 {
				return nil, fmt.Errorf("match offset %d beyond output start (output len %d)", seq.offset, len(dst))
			}
			// May overlap — copy byte by byte
			for j := 0; j < seq.matchLen; j++ {
				dst = append(dst, dst[matchStart+j])
			}
		}
	}

	// Remaining literals
	if litPos < len(literals) {
		dst = append(dst, literals[litPos:]...)
	}

	return dst, nil
}

func zstdGetSeqTable(mode byte, data []byte, pos *int, defaultProbs []int16, maxLog int, maxSym int) (*zstdFSETable, error) {
	switch mode {
	case 0: // Predefined
		return zstdBuildFSEFromProbs(defaultProbs, maxLog, maxSym)
	case 1: // RLE
		if *pos >= len(data) {
			return nil, fmt.Errorf("RLE mode missing byte")
		}
		sym := data[*pos]
		*pos++
		return zstdBuildRLEFSETable(sym), nil
	case 2: // FSE_Compressed
		tbl, consumed, err := zstdBuildFSETableFromHeader(data[*pos:], maxLog)
		if err != nil {
			return nil, err
		}
		*pos += consumed
		return tbl, nil
	case 3: // Repeat — not handled yet
		return nil, fmt.Errorf("repeat mode not supported")
	}
	return nil, fmt.Errorf("unknown mode %d", mode)
}

func zstdBuildRLEFSETable(sym byte) *zstdFSETable {
	return &zstdFSETable{
		symbols:    []byte{sym},
		numBits:    []byte{0},
		newState:   []uint16{0},
		stateCount: 1,
		accuracyLog: 0,
	}
}

func zstdBuildFSEFromProbs(probs []int16, accuracyLog int, maxSym int) (*zstdFSETable, error) {
	tableSize := 1 << uint(accuracyLog)
	table := &zstdFSETable{
		symbols:    make([]byte, tableSize),
		numBits:    make([]byte, tableSize),
		newState:   make([]uint16, tableSize),
		stateCount: tableSize,
		accuracyLog: accuracyLog,
	}

	highThreshold := tableSize - 1
	for sym, p := range probs {
		if p == -1 {
			table.symbols[highThreshold] = byte(sym)
			highThreshold--
		}
	}

	step := (tableSize >> 1) + (tableSize >> 3) + 3
	mask := tableSize - 1
	pos := 0
	for sym, p := range probs {
		if p <= 0 {
			continue
		}
		for i := int16(0); i < p; i++ {
			table.symbols[pos] = byte(sym)
			pos = (pos + step) & mask
			for pos > highThreshold {
				pos = (pos + step) & mask
			}
		}
	}

	symNext := make([]uint16, len(probs))
	for sym, p := range probs {
		if p == -1 {
			symNext[sym] = 1
		} else if p > 0 {
			symNext[sym] = uint16(p)
		}
	}

	for i := 0; i < tableSize; i++ {
		sym := table.symbols[i]
		nb := byte(accuracyLog) - zstdHighBit(uint32(symNext[sym]))
		table.numBits[i] = nb
		table.newState[i] = (symNext[sym] << nb) - uint16(tableSize)
		symNext[sym]++
	}

	return table, nil
}

// ──────────────────────────── bit readers ────────────────────────────

// Reverse bit reader (reads from end of data, MSB first)
type zstdBitReaderRev struct {
	data   []byte
	bitOff int // current bit offset from start (decreasing)
}

func newZstdBitReaderReverse(data []byte) *zstdBitReaderRev {
	return &zstdBitReaderRev{data: data, bitOff: len(data) * 8}
}

func (br *zstdBitReaderRev) initReverse() error {
	if len(br.data) == 0 {
		return fmt.Errorf("empty bitstream")
	}
	// Find the leading 1 bit in the last byte
	last := br.data[len(br.data)-1]
	if last == 0 {
		return fmt.Errorf("padding byte is zero")
	}
	// Skip the sentinel 1 bit
	bits := 7
	for (last>>uint(bits))&1 == 0 {
		bits--
	}
	br.bitOff = (len(br.data)-1)*8 + bits
	return nil
}

func (br *zstdBitReaderRev) bitsLeft() int {
	return br.bitOff
}

func (br *zstdBitReaderRev) peekBits(n int) int {
	if n == 0 || br.bitOff < n {
		return 0
	}
	// We need n bits ending at bitOff
	start := br.bitOff - n
	val := 0
	for i := 0; i < n; i++ {
		bitIdx := start + i
		byteIdx := bitIdx / 8
		bitInByte := uint(bitIdx % 8)
		if byteIdx < len(br.data) {
			val |= int((br.data[byteIdx]>>bitInByte)&1) << uint(i)
		}
	}
	return val
}

func (br *zstdBitReaderRev) readBits(n int) int {
	val := br.peekBits(n)
	br.bitOff -= n
	return val
}

func (br *zstdBitReaderRev) skipBits(n int) {
	br.bitOff -= n
}

// Forward bit reader
type zstdBitReaderForward struct {
	data   []byte
	bitPos int
}

func (br *zstdBitReaderForward) readFwd(n int) uint32 {
	if n == 0 {
		return 0
	}
	var val uint32
	for i := 0; i < n; i++ {
		byteIdx := br.bitPos / 8
		bitIdx := uint(br.bitPos % 8)
		if byteIdx < len(br.data) {
			val |= uint32((br.data[byteIdx]>>bitIdx)&1) << uint(i)
		}
		br.bitPos++
	}
	return val
}

// ──────────────────────────── Predefined FSE tables (RFC 8878 §4) ────────────────────────────

// Literal Length default distribution (accuracy log = 6)
var zstdLLDefaultProbs = []int16{
	4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
	-1, -1, -1, -1,
}

// Match Length default distribution (accuracy log = 6)
var zstdMLDefaultProbs = []int16{
	1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
	-1, -1, -1, -1, -1,
}

// Offset default distribution (accuracy log = 5)
var zstdOFDefaultProbs = []int16{
	1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
}

// Literal length baselines and extra bits
var zstdLLBaseline = [36]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
	8192, 16384, 32768, 65536,
}

var zstdLLBits = [36]int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
	13, 14, 15, 16,
}

// Match length baselines and extra bits
var zstdMLBaseline = [53]int{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
	19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
	35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
	4099, 8195, 16387, 32771, 65539,
}

var zstdMLBits = [53]int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16,
}
