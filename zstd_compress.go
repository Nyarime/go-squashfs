package squashfs

// Pure Go Zstandard (RFC 8878) compressor.
// Produces valid zstd frames decodable by any compliant decoder.
// Strategy: raw literals + RLE FSE tables (all sequences must share same codes).
// Falls back to raw blocks when sequences have mixed codes.

import (
	"encoding/binary"
)

// ZstdCompress compresses data using Zstandard format (RFC 8878).
// level: 1 (fastest) to 19 (best compression). Default 3 if 0.
func ZstdCompress(src []byte, level int) []byte {
	return ZstdCompressWithDict(src, level, nil)
}

// ZstdCompressWithDict compresses with a dictionary.
func ZstdCompressWithDict(src []byte, level int, dict []byte) []byte {
	if level <= 0 {
		level = 3
	}
	if level > 19 {
		level = 19
	}
	_ = dict // accepted for API compat, not used in matching

	if len(src) == 0 {
		return zstdEmptyFrame()
	}
	if len(src) <= 16 {
		return zstdRawFrame(src)
	}
	return zstdCompressFrame(src, level)
}

func zstdEmptyFrame() []byte {
	var buf [9]byte
	binary.LittleEndian.PutUint32(buf[0:4], zstdMagic)
	buf[4] = 1 << 5 // single segment
	buf[5] = 0      // FCS = 0
	buf[6] = 1      // last raw block, size 0
	return buf[:9]
}

func zstdRawFrame(src []byte) []byte {
	out := make([]byte, 0, 4+2+3+len(src))
	out = zstdAppendU32(out, zstdMagic)
	fhd, fcs := zstdMakeFCS(uint64(len(src)))
	fhd |= 1 << 5
	out = append(out, fhd)
	out = append(out, fcs...)
	bh := uint32(1) | (uint32(len(src)) << 3) // last=1, type=raw, size
	out = append(out, byte(bh), byte(bh>>8), byte(bh>>16))
	out = append(out, src...)
	return out
}

func zstdCompressFrame(src []byte, level int) []byte {
	out := make([]byte, 0, len(src)+64)
	out = zstdAppendU32(out, zstdMagic)
	fhd, fcs := zstdMakeFCS(uint64(len(src)))
	fhd |= 1 << 5
	out = append(out, fhd)
	out = append(out, fcs...)

	const maxBlock = 128 * 1024
	for i := 0; i < len(src); {
		end := i + maxBlock
		if end > len(src) {
			end = len(src)
		}
		last := end == len(src)
		block := src[i:end]

		compressed := zstdTryCompressBlock(block, level)
		if compressed != nil && len(compressed) < len(block) {
			bh := uint32(2 << 1) | (uint32(len(compressed)) << 3)
			if last {
				bh |= 1
			}
			out = append(out, byte(bh), byte(bh>>8), byte(bh>>16))
			out = append(out, compressed...)
		} else {
			bh := uint32(len(block)) << 3
			if last {
				bh |= 1
			}
			out = append(out, byte(bh), byte(bh>>8), byte(bh>>16))
			out = append(out, block...)
		}
		i = end
	}
	return out
}

func zstdMakeFCS(size uint64) (fhd byte, fcs []byte) {
	switch {
	case size <= 255:
		return 0, []byte{byte(size)}
	case size <= 65535+256:
		v := uint16(size - 256)
		return 1 << 6, []byte{byte(v), byte(v >> 8)}
	case size <= 0xFFFFFFFF:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(size))
		return 2 << 6, b
	default:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, size)
		return 3 << 6, b
	}
}

func zstdAppendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// ──────────────────────────── block compression ────────────────────────────

type zstdSeq struct {
	litLen   int
	offset   int // actual offset (not coded)
	matchLen int
}

func zstdTryCompressBlock(src []byte, level int) []byte {
	if len(src) < 8 {
		return nil
	}
	seqs := zstdFindSeqs(src, level)
	if len(seqs) == 0 {
		return nil
	}
	return zstdBuildBlock(src, seqs)
}

// ──────────────────────────── LZ77 match finder ────────────────────────────

const (
	zcMinMatch = 4
	zcHashLog  = 16
	zcHashMask = (1 << zcHashLog) - 1
	zcMaxOff   = 4 << 20 // 4MB
)

func zcHash4(b []byte) uint32 {
	v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	return (v * 2654435761) >> (32 - zcHashLog)
}

func zstdFindSeqs(src []byte, level int) []zstdSeq {
	n := len(src)
	if n < zcMinMatch {
		return nil
	}

	ht := make([]int32, 1<<zcHashLog)
	for i := range ht {
		ht[i] = -1
	}

	lazy := level >= 4
	maxDepth := 1
	if level >= 4 {
		maxDepth = 4
	}
	if level >= 8 {
		maxDepth = 16
	}

	chain := make([]int32, n)
	for i := range chain {
		chain[i] = -1
	}

	var seqs []zstdSeq
	pos := 0
	litStart := 0

	for pos+zcMinMatch <= n {
		h := zcHash4(src[pos:])
		prev := ht[h]
		chain[pos] = prev
		ht[h] = int32(pos)

		bestLen, bestOff := zcBestMatch(src, chain, int(prev), pos, maxDepth)

		if bestLen < zcMinMatch {
			pos++
			continue
		}

		if lazy && pos+1+zcMinMatch <= n {
			h2 := zcHash4(src[pos+1:])
			prev2 := ht[h2]
			chain[pos+1] = prev2
			ht[h2] = int32(pos + 1)
			l2, o2 := zcBestMatch(src, chain, int(prev2), pos+1, maxDepth)
			if l2 > bestLen {
				pos++
				bestLen = l2
				bestOff = o2
			}
		}

		seqs = append(seqs, zstdSeq{
			litLen:   pos - litStart,
			offset:   bestOff,
			matchLen: bestLen,
		})

		end := pos + bestLen
		pos++
		for pos < end && pos+zcMinMatch <= n {
			h := zcHash4(src[pos:])
			chain[pos] = ht[h]
			ht[h] = int32(pos)
			pos++
		}
		if pos < end {
			pos = end
		}
		litStart = pos
	}
	return seqs
}

func zcBestMatch(src []byte, chain []int32, cand, pos, maxDepth int) (bestLen, bestOff int) {
	for cand >= 0 && maxDepth > 0 {
		off := pos - cand
		if off <= 0 || off > zcMaxOff {
			break
		}
		ml := zcMatchLen(src, cand, pos)
		if ml >= zcMinMatch && ml > bestLen {
			bestLen = ml
			bestOff = off
		}
		cand = int(chain[cand])
		maxDepth--
	}
	return
}

func zcMatchLen(src []byte, a, b int) int {
	maxL := len(src) - b
	if len(src)-a < maxL {
		maxL = len(src) - a
	}
	l := 0
	for l < maxL && src[a+l] == src[b+l] {
		l++
	}
	return l
}

// ──────────────────────────── block building ────────────────────────────

func zstdBuildBlock(src []byte, seqs []zstdSeq) []byte {
	// Collect literals
	var lits []byte
	pos := 0
	for _, s := range seqs {
		lits = append(lits, src[pos:pos+s.litLen]...)
		pos += s.litLen + s.matchLen
	}
	trailing := src[pos:]
	lits = append(lits, trailing...)

	// Encode offset values and check repeated offsets
	type codedSeq struct {
		llCode   int
		llExtra  uint32
		llBits   int
		ofCode   int
		ofExtra  uint32
		ofBits   int
		mlCode   int
		mlExtra  uint32
		mlBits   int
	}

	offHist := [3]int{1, 4, 8}
	coded := make([]codedSeq, len(seqs))

	for i, s := range seqs {
		// Literal length
		coded[i].llCode, coded[i].llBits, coded[i].llExtra = zcLLCode(s.litLen)
		// Match length
		coded[i].mlCode, coded[i].mlBits, coded[i].mlExtra = zcMLCode(s.matchLen)

		// Offset with repeat detection
		off := s.offset
		repIdx := -1
		for j := 0; j < 3; j++ {
			if off == offHist[j] {
				repIdx = j
				break
			}
		}

		if repIdx >= 0 && s.litLen > 0 {
			// Repeated offset: ofCode=repIdx (0,1,2), 0 extra bits
			coded[i].ofCode = repIdx
			coded[i].ofBits = 0
			coded[i].ofExtra = 0
			if repIdx > 0 {
				tmp := offHist[repIdx]
				copy(offHist[1:repIdx+1], offHist[:repIdx])
				offHist[0] = tmp
			}
		} else if repIdx == 0 && s.litLen == 0 {
			// litLen==0, offset==offHist[0] → use rep offset 0 which means offHist[0]
			// But with litLen==0 and offset code 1, decoder uses offHist[1].
			// This is tricky. Use explicit offset to be safe.
			coded[i].ofCode, coded[i].ofBits, coded[i].ofExtra = zcOFCode(off + 3)
			offHist[2] = offHist[1]
			offHist[1] = offHist[0]
			offHist[0] = off
		} else {
			// Explicit offset
			coded[i].ofCode, coded[i].ofBits, coded[i].ofExtra = zcOFCode(off + 3)
			offHist[2] = offHist[1]
			offHist[1] = offHist[0]
			offHist[0] = off
		}
	}

	// Check if all sequences share the same code for each table
	llSame, ofSame, mlSame := true, true, true
	for i := 1; i < len(coded); i++ {
		if coded[i].llCode != coded[0].llCode {
			llSame = false
		}
		if coded[i].ofCode != coded[0].ofCode {
			ofSame = false
		}
		if coded[i].mlCode != coded[0].mlCode {
			mlSame = false
		}
	}

	// If any table needs predefined mode, use predefined tables
	// Build sequence header
	nbSeq := len(seqs)
	var hdr []byte
	if nbSeq < 128 {
		hdr = append(hdr, byte(nbSeq))
	} else if nbSeq < 0x7F00 {
		hdr = append(hdr, byte((nbSeq>>8)+128), byte(nbSeq))
	} else {
		hdr = append(hdr, 255, byte(nbSeq-0x7F00), byte((nbSeq-0x7F00)>>8))
	}

	// Mode byte: LL(6:7) OF(4:5) ML(2:3)
	// 0=predefined, 1=RLE
	var llMode, ofMode, mlMode byte
	if llSame {
		llMode = 1
	}
	if ofSame {
		ofMode = 1
	}
	if mlSame {
		mlMode = 1
	}
	hdr = append(hdr, (llMode<<6)|(ofMode<<4)|(mlMode<<2))

	// RLE bytes
	if llSame {
		hdr = append(hdr, byte(coded[0].llCode))
	}
	if ofSame {
		hdr = append(hdr, byte(coded[0].ofCode))
	}
	if mlSame {
		hdr = append(hdr, byte(coded[0].mlCode))
	}

	// Build the bitstream
	// For predefined tables, we need proper FSE state encoding.
	// The bitstream is read in reverse (from end). We build it forward then reverse.
	//
	// Structure (in decode/read order, which is reverse of byte order):
	//   1. Read initial states: LL state (6 bits), OF state (5 bits), ML state (6 bits)
	//   2. For each sequence i=0..n-1:
	//      a. Decode symbols from current states (ofCode, mlCode, llCode)
	//      b. Read extra bits: OF extra (ofCode bits), ML extra (mlBits), LL extra (llBits)
	//      c. If i < n-1: read state update bits: LL (nb bits), ML (nb bits), OF (nb bits)
	//
	// Writing in forward order (which becomes reversed):
	//   We write bits from the LAST thing the decoder reads to the FIRST.
	//   Decoder reads: init states, then seq0 extras, seq0 updates, seq1 extras, ...
	//   So we write in reverse: ..., seq0 updates(reversed), seq0 extras(reversed), init states
	//   Then reverse the whole thing.
	//
	// Actually easier: write in decoder-read order into a bit accumulator, then
	// output the bitstream reversed (last byte first, MSB at top).

	var bw zcBitWriter

	// We need FSE tables for predefined mode
	if !llSame || !ofSame || !mlSame {
		zcInitPredTables()
	}

	// Determine initial states (the state that will decode to the symbol of seq[0])
	var llState, ofState, mlState int
	if !llSame {
		llState = zcFindState(&zcPredLL, coded[0].llCode)
	}
	if !ofSame {
		ofState = zcFindState(&zcPredOF, coded[0].ofCode)
	}
	if !mlSame {
		mlState = zcFindState(&zcPredML, coded[0].mlCode)
	}

	// Write initial states (decoder reads these first from the reversed stream)
	if !llSame {
		bw.writeBits(uint64(llState), 6) // LL accuracy log = 6
	}
	if !ofSame {
		bw.writeBits(uint64(ofState), 5) // OF accuracy log = 5
	}
	if !mlSame {
		bw.writeBits(uint64(mlState), 6) // ML accuracy log = 6
	}

	// Write sequences
	for i := 0; i < nbSeq; i++ {
		c := coded[i]

		// Extra bits for this sequence (decoder reads: OF extra, ML extra, LL extra)
		if c.ofBits > 0 {
			bw.writeBits(uint64(c.ofExtra), c.ofBits)
		}
		if c.mlBits > 0 {
			bw.writeBits(uint64(c.mlExtra), c.mlBits)
		}
		if c.llBits > 0 {
			bw.writeBits(uint64(c.llExtra), c.llBits)
		}

		// State updates (not for last sequence)
		if i < nbSeq-1 {
			// For each table: find a new state that decodes to next symbol,
			// then write the low bits that the decoder will read to reconstruct the state.
			// newState[curState] + readBits(numBits[curState]) = nextState
			// So we need: write numBits[curState] low bits of (nextState - newState[curState])
			if !llSame {
				nextState := zcFindState(&zcPredLL, coded[i+1].llCode)
				nb := int(zcPredLL.numBits[llState])
				lowBits := nextState - int(zcPredLL.newState[llState])
				bw.writeBits(uint64(lowBits), nb)
				llState = nextState
			}
			if !mlSame {
				nextState := zcFindState(&zcPredML, coded[i+1].mlCode)
				nb := int(zcPredML.numBits[mlState])
				lowBits := nextState - int(zcPredML.newState[mlState])
				bw.writeBits(uint64(lowBits), nb)
				mlState = nextState
			}
			if !ofSame {
				nextState := zcFindState(&zcPredOF, coded[i+1].ofCode)
				nb := int(zcPredOF.numBits[ofState])
				lowBits := nextState - int(zcPredOF.newState[ofState])
				bw.writeBits(uint64(lowBits), nb)
				ofState = nextState
			}
		}
	}

	stream := bw.finishReverse()

	// Assemble block: literals section + sequence header + bitstream
	litSec := zcRawLiterals(lits)
	out := make([]byte, 0, len(litSec)+len(hdr)+len(stream))
	out = append(out, litSec...)
	out = append(out, hdr...)
	out = append(out, stream...)
	return out
}

// ──────────────────────────── raw literals ────────────────────────────

func zcRawLiterals(lits []byte) []byte {
	n := len(lits)
	if n < 32 {
		// 1-byte header: type=0(2 bits) | sizeFormat=0(2 bits) | size(4 bits)
		// Regenerated_Size = Header[0] >> 3 → 5 bits max 31
		out := make([]byte, 0, 1+n)
		out = append(out, byte(n<<3))
		out = append(out, lits...)
		return out
	}
	if n < 4096 {
		// 2-byte header, sizeFormat=1
		// byte0 = type(2) | sizeFormat(2) | size_low(4)
		// byte1 = size_high(8)
		// size = (byte0>>4) | (byte1<<4)
		out := make([]byte, 0, 2+n)
		out = append(out, byte(0|(1<<2)|(byte(n&0xF)<<4)), byte(n>>4))
		out = append(out, lits...)
		return out
	}
	// 3-byte header, sizeFormat=3
	out := make([]byte, 0, 3+n)
	out = append(out, byte(0|(3<<2)|(byte(n&0xF)<<4)), byte(n>>4), byte(n>>12))
	out = append(out, lits...)
	return out
}

// ──────────────────────────── code tables ────────────────────────────

func zcLLCode(litLen int) (code, extraBits int, extra uint32) {
	if litLen < 16 {
		return litLen, 0, 0
	}
	for c := 16; c < 36; c++ {
		if c == 35 || litLen < zstdLLBaseline[c+1] {
			return c, zstdLLBits[c], uint32(litLen - zstdLLBaseline[c])
		}
	}
	return 35, zstdLLBits[35], uint32(litLen - zstdLLBaseline[35])
}

func zcMLCode(matchLen int) (code, extraBits int, extra uint32) {
	if matchLen < 3 {
		matchLen = 3
	}
	for c := 0; c < 53; c++ {
		if c == 52 || matchLen < zstdMLBaseline[c+1] {
			return c, zstdMLBits[c], uint32(matchLen - zstdMLBaseline[c])
		}
	}
	return 52, zstdMLBits[52], uint32(matchLen - zstdMLBaseline[52])
}

func zcOFCode(offset int) (code, extraBits int, extra uint32) {
	if offset < 1 {
		offset = 1
	}
	code = 0
	v := offset
	for v > 1 {
		v >>= 1
		code++
	}
	extra = uint32(offset - (1 << uint(code)))
	extraBits = code
	return
}

// ──────────────────────────── predefined FSE tables ────────────────────────────

type zcPredTable struct {
	symbols   []byte
	numBits   []byte
	newState  []uint16
	sym2state [][]int // symbol → list of valid states
	accLog    int
}

var (
	zcPredLL    zcPredTable
	zcPredOF    zcPredTable
	zcPredML    zcPredTable
	zcPredReady bool
)

func zcInitPredTables() {
	if zcPredReady {
		return
	}
	zcBuildPred(&zcPredLL, zstdLLDefaultProbs, 6)
	zcBuildPred(&zcPredOF, zstdOFDefaultProbs, 5)
	zcBuildPred(&zcPredML, zstdMLDefaultProbs, 6)
	zcPredReady = true
}

func zcBuildPred(tbl *zcPredTable, probs []int16, accLog int) {
	tableSize := 1 << uint(accLog)
	tbl.accLog = accLog
	tbl.symbols = make([]byte, tableSize)
	tbl.numBits = make([]byte, tableSize)
	tbl.newState = make([]uint16, tableSize)

	highThreshold := tableSize - 1
	for sym, p := range probs {
		if p == -1 {
			tbl.symbols[highThreshold] = byte(sym)
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
			tbl.symbols[pos] = byte(sym)
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
		sym := tbl.symbols[i]
		nb := byte(accLog) - zstdHighBit(uint32(symNext[sym]))
		tbl.numBits[i] = nb
		tbl.newState[i] = (symNext[sym] << nb) - uint16(tableSize)
		symNext[sym]++
	}

	// Build sym2state map
	tbl.sym2state = make([][]int, 256)
	for i := 0; i < tableSize; i++ {
		s := tbl.symbols[i]
		tbl.sym2state[s] = append(tbl.sym2state[s], i)
	}
}

// zcFindState returns a state index that decodes to the given symbol.
func zcFindState(tbl *zcPredTable, sym int) int {
	if sym < 256 && len(tbl.sym2state[sym]) > 0 {
		return tbl.sym2state[sym][0]
	}
	return 0
}

// ──────────────────────────── bitstream writer ────────────────────────────

// The zstd bitstream is read from the end of the byte buffer.
// Bits are consumed from MSB to LSB within the stream.
// We accumulate bits in decode-order, then reverse the byte stream.

type zcBitWriter struct {
	// Accumulate bit entries in decoder-read order
	entries []zcBitEntry
}

type zcBitEntry struct {
	val    uint64
	nbBits int
}

func (w *zcBitWriter) writeBits(val uint64, nbBits int) {
	if nbBits > 0 {
		w.entries = append(w.entries, zcBitEntry{val, nbBits})
	}
}

// finishReverse produces the bitstream.
// The decoder (zstdBitReaderRev) reads from high bit positions down.
// peekBits(n) reads bits [bitOff-n .. bitOff-1] where position bitOff-n = bit 0 (LSB).
// So values are stored LSB at low position, MSB at high position.
// Decoder consumes from high positions downward.
func (w *zcBitWriter) finishReverse() []byte {
	// Total bits needed
	totalBits := 1 // sentinel
	for _, e := range w.entries {
		totalBits += e.nbBits
	}

	nBytes := (totalBits + 7) / 8
	buf := make([]byte, nBytes)

	// We fill from the top (highest bit position) down.
	// bitPos tracks the next bit position to write (decreasing).
	bitPos := nBytes*8 - 1

	// Sentinel bit at the top
	buf[bitPos/8] |= 1 << uint(bitPos%8)
	bitPos--

	// Write entries in forward order.
	// The decoder reads each entry by peeking n bits at [bitOff-n..bitOff-1].
	// bit at (bitOff-n) = bit 0 (LSB), bit at (bitOff-1) = bit (n-1) (MSB).
	// So MSB goes at the higher position (written first as we go down).
	for _, e := range w.entries {
		// Write from MSB (bit n-1) at high pos down to LSB (bit 0) at low pos
		for b := e.nbBits - 1; b >= 0; b-- {
			if bitPos < 0 {
				break
			}
			if (e.val>>uint(b))&1 != 0 {
				buf[bitPos/8] |= 1 << uint(bitPos%8)
			}
			bitPos--
		}
	}

	return buf
}
