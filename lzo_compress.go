package squashfs

// Pure Go LZO1X-1 compressor
// Reference: http://www.oberhumer.com/opensource/lzo/
// Produces output compatible with miniLZO / kernel LZO

import (
	"bytes"
	"io"
)

const (
	lzoHashSize  = 1 << 14 // 16384
	lzoMaxLitRun = 18      // Before we must emit a literal run header
)

type lzoCompressWriter struct {
	buf bytes.Buffer
}

func LzoNewWriter(w io.Writer) io.WriteCloser {
	return &lzoCompressWriter{}
}

// LzoCompress compresses data using LZO1X-1 algorithm
func LzoCompress(src []byte) ([]byte, error) {
	if len(src) <= 13 {
		// Too short to compress — emit as literal
		out := make([]byte, 0, len(src)+3)
		out = append(out, byte(17+len(src)))
		out = append(out, src...)
		out = append(out, 17, 0, 0) // end marker
		return out, nil
	}

	var dst []byte
	hashTable := make([]int, lzoHashSize)
	for i := range hashTable {
		hashTable[i] = -1
	}

	ip := 0
	litStart := 0

	emitLiterals := func(start, count int) {
		if count <= 0 {
			return
		}
		if count <= 3 {
			// Trailing literal count — appended to previous match
			// If no previous match, use long literal form
			if len(dst) == 0 {
				if count <= 238 {
					dst = append(dst, byte(17+count))
				} else {
					dst = append(dst, byte(17))
					c := count - 3
					for c >= 255 {
						dst = append(dst, 0)
						c -= 255
					}
					dst = append(dst, byte(c))
				}
			} else {
				// Encode in last match's trailing literal bits
				dst[len(dst)-2] |= byte(count)
			}
		} else if count <= 18 {
			dst = append(dst, byte(count-3))
		} else {
			dst = append(dst, 0)
			c := count - 18
			for c >= 255 {
				dst = append(dst, 0)
				c -= 255
			}
			dst = append(dst, byte(c))
		}
		dst = append(dst, src[start:start+count]...)
	}

	hash := func(pos int) int {
		if pos+4 > len(src) {
			return 0
		}
		v := uint32(src[pos]) | uint32(src[pos+1])<<8 |
			uint32(src[pos+2])<<16 | uint32(src[pos+3])<<24
		return int(((v * 0x1E35A7BD) >> 18) & (lzoHashSize - 1))
	}

	// Main compression loop
	for ip+4 < len(src) {
		h := hash(ip)
		ref := hashTable[h]
		hashTable[h] = ip

		dist := ip - ref
		if ref < 0 || dist > 0x3FFF+0x800 ||
			src[ref] != src[ip] || src[ref+1] != src[ip+1] ||
			src[ref+2] != src[ip+2] || src[ref+3] != src[ip+3] {
			ip++
			continue
		}

		// Found match — emit pending literals
		litCount := ip - litStart
		emitLiterals(litStart, litCount)

		// Find match length
		matchLen := 4
		for ip+matchLen < len(src) && ref+matchLen < ip &&
			src[ip+matchLen] == src[ref+matchLen] && matchLen < 264 {
			matchLen++
		}

		// Emit match
		if dist <= 0x800 && matchLen <= 8 {
			// Short match: 2 bytes, length 3-8, offset 1-2048
			ml := matchLen - 1
			d := dist - 1
			dst = append(dst, byte(((d>>8)<<5)|((ml&7)<<2)))
			dst = append(dst, byte(d&0xFF))
		} else {
			// Long match: 3 bytes, offset 1-16384
			d := dist - 1
			ml := matchLen - 2
			if ml <= 31 {
				dst = append(dst, byte(32|ml))
			} else {
				dst = append(dst, 32)
				ml -= 31
				for ml >= 255 {
					dst = append(dst, 0)
					ml -= 255
				}
				dst = append(dst, byte(ml))
			}
			dst = append(dst, byte((d<<2)&0xFF))
			dst = append(dst, byte(d>>6))
		}

		ip += matchLen
		litStart = ip
	}

	// Emit remaining literals
	remaining := len(src) - litStart
	if remaining > 0 {
		emitLiterals(litStart, remaining)
	}

	// End marker
	dst = append(dst, 17, 0, 0)

	return dst, nil
}

func (w *lzoCompressWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	return len(p), nil
}

func (w *lzoCompressWriter) Close() error {
	return nil
}
