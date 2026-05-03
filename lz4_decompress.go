package squashfs

// Pure Go LZ4 block decompressor
// Reference: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
// SquashFS uses raw LZ4 block format (no frame header)

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type lz4Reader struct {
	buf *bytes.Reader
}

// Lz4NewReader creates a new LZ4 decompressor reader
func Lz4NewReader(r io.Reader) (io.ReadCloser, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	decompressed, err := lz4BlockDecompress(data)
	if err != nil {
		return nil, fmt.Errorf("lz4 decompress: %w", err)
	}

	return &lz4Reader{
		buf: bytes.NewReader(decompressed),
	}, nil
}

func (r *lz4Reader) Read(p []byte) (int, error) {
	return r.buf.Read(p)
}

func (r *lz4Reader) Close() error {
	return nil
}

// Lz4FrameDecompress handles LZ4 frame format (magic 0x184D2204)
func Lz4FrameDecompress(src []byte) ([]byte, error) {
	if len(src) < 7 {
		return nil, fmt.Errorf("lz4 frame too short")
	}

	magic := binary.LittleEndian.Uint32(src[:4])
	if magic != 0x184D2204 {
		// No frame header — try raw block decompress
		return lz4BlockDecompress(src)
	}

	// Parse frame descriptor
	flg := src[4]
	// bd := src[5]
	hasContentSize := (flg & 0x08) != 0

	headerSize := 7 // magic(4) + FLG(1) + BD(1) + HC(1)
	if hasContentSize {
		headerSize += 8
	}

	if len(src) < headerSize {
		return nil, fmt.Errorf("lz4 frame header too short")
	}

	pos := headerSize
	var result []byte

	for pos+4 <= len(src) {
		blockSize := int(binary.LittleEndian.Uint32(src[pos : pos+4]))
		pos += 4

		if blockSize == 0 {
			break // End mark
		}

		isUncompressed := (blockSize & 0x80000000) != 0
		blockSize &= 0x7FFFFFFF

		if pos+blockSize > len(src) {
			break
		}

		blockData := src[pos : pos+blockSize]
		pos += blockSize

		if isUncompressed {
			result = append(result, blockData...)
		} else {
			decompressed, err := lz4BlockDecompress(blockData)
			if err != nil {
				return nil, fmt.Errorf("lz4 block decompress: %w", err)
			}
			result = append(result, decompressed...)
		}
	}

	return result, nil
}

// lz4BlockDecompress decompresses a single LZ4 block (raw format, no frame)
func lz4BlockDecompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}

	// Pre-allocate with generous estimate
	dst := make([]byte, 0, len(src)*4)
	ip := 0

	for ip < len(src) {
		// Token
		token := src[ip]
		ip++

		// Literal length
		litLen := int(token >> 4)
		if litLen == 15 {
			for ip < len(src) {
				s := src[ip]
				ip++
				litLen += int(s)
				if s != 255 {
					break
				}
			}
		}

		// Copy literals
		if ip+litLen > len(src) {
			// Allow partial copy at end of stream
			litLen = len(src) - ip
		}
		dst = append(dst, src[ip:ip+litLen]...)
		ip += litLen

		// Check if this is the last token (no match after last literals)
		if ip >= len(src) {
			break
		}

		// Match offset (2 bytes, little-endian)
		if ip+2 > len(src) {
			break
		}
		offset := int(binary.LittleEndian.Uint16(src[ip : ip+2]))
		ip += 2

		if offset == 0 {
			return nil, fmt.Errorf("lz4: invalid zero offset")
		}

		// Match length
		matchLen := int(token&0x0F) + 4 // minimum match = 4
		if (token & 0x0F) == 15 {
			for ip < len(src) {
				s := src[ip]
				ip++
				matchLen += int(s)
				if s != 255 {
					break
				}
			}
		}

		// Copy match (byte-by-byte for overlapping)
		matchPos := len(dst) - offset
		if matchPos < 0 {
			return nil, fmt.Errorf("lz4: match offset %d exceeds output %d", offset, len(dst))
		}

		for i := 0; i < matchLen; i++ {
			dst = append(dst, dst[matchPos+i])
		}
	}

	return dst, nil
}
