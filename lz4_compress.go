package squashfs

// Pure Go LZ4 block compressor
// Reference: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
// Produces raw LZ4 blocks (no frame header) as used by SquashFS

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	lz4HashBits = 16
	lz4HashSize = 1 << lz4HashBits
	lz4MinMatch = 4
	lz4MaxDist  = 65535
)

type lz4CompressWriter struct {
	buf bytes.Buffer
}

func Lz4NewWriter(w io.Writer) io.WriteCloser {
	return &lz4CompressWriter{}
}

// Lz4BlockCompress compresses data using LZ4 block format
func Lz4BlockCompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}

	// Worst case: input + overhead
	dst := make([]byte, 0, len(src)+len(src)/255+16)

	hashTable := make([]int, lz4HashSize)
	for i := range hashTable {
		hashTable[i] = -1
	}

	hash4 := func(pos int) int {
		v := binary.LittleEndian.Uint32(src[pos:])
		return int((v * 2654435761) >> (32 - lz4HashBits))
	}

	ip := 0
	anchor := 0

	for ip+lz4MinMatch < len(src) {
		h := hash4(ip)
		ref := hashTable[h]
		hashTable[h] = ip

		if ref < 0 || ip-ref > lz4MaxDist ||
			binary.LittleEndian.Uint32(src[ip:]) != binary.LittleEndian.Uint32(src[ref:]) {
			ip++
			continue
		}

		// Match found — encode token
		litLen := ip - anchor

		// Extend match forward
		matchLen := lz4MinMatch
		for ip+matchLen < len(src) && ref+matchLen < ip &&
			src[ip+matchLen] == src[ref+matchLen] {
			matchLen++
		}

		// Token
		ml := matchLen - lz4MinMatch
		token := byte(0)
		if litLen >= 15 {
			token = 0xF0
		} else {
			token = byte(litLen << 4)
		}
		if ml >= 15 {
			token |= 0x0F
		} else {
			token |= byte(ml)
		}
		dst = append(dst, token)

		// Literal length overflow
		if litLen >= 15 {
			remaining := litLen - 15
			for remaining >= 255 {
				dst = append(dst, 255)
				remaining -= 255
			}
			dst = append(dst, byte(remaining))
		}

		// Literals
		dst = append(dst, src[anchor:anchor+litLen]...)

		// Offset (2 bytes LE)
		offset := ip - ref
		dst = append(dst, byte(offset), byte(offset>>8))

		// Match length overflow
		if ml >= 15 {
			remaining := ml - 15
			for remaining >= 255 {
				dst = append(dst, 255)
				remaining -= 255
			}
			dst = append(dst, byte(remaining))
		}

		ip += matchLen
		anchor = ip
	}

	// Last literals (mandatory — LZ4 requires last 5 bytes to be literals)
	litLen := len(src) - anchor
	if litLen > 0 {
		token := byte(0)
		if litLen >= 15 {
			token = 0xF0
		} else {
			token = byte(litLen << 4)
		}
		dst = append(dst, token)

		if litLen >= 15 {
			remaining := litLen - 15
			for remaining >= 255 {
				dst = append(dst, 255)
				remaining -= 255
			}
			dst = append(dst, byte(remaining))
		}

		dst = append(dst, src[anchor:]...)
	}

	return dst, nil
}

// Lz4FrameCompress wraps a block in LZ4 frame format
func Lz4FrameCompress(src []byte) ([]byte, error) {
	block, err := Lz4BlockCompress(src)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	// Frame magic
	binary.Write(&buf, binary.LittleEndian, uint32(0x184D2204))

	// Frame descriptor (FLG + BD + HC)
	flg := byte(0x60) // version 01, block independence
	bd := byte(0x70)   // max block size = 4MB
	hc := byte(0)      // checksum placeholder (simplified)
	buf.Write([]byte{flg, bd, hc})

	// Block
	binary.Write(&buf, binary.LittleEndian, uint32(len(block)))
	buf.Write(block)

	// End mark
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	return buf.Bytes(), nil
}

func (w *lz4CompressWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	return len(p), nil
}

func (w *lz4CompressWriter) Close() error {
	return nil
}
