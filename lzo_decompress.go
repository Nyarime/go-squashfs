package squashfs

// Pure Go LZO1X decompressor (miniLZO compatible)
// Reference: http://www.oberhumer.com/opensource/lzo/
// Adapted from go-ubi/ubifs/lzo.go for squashfs integration

import (
	"bytes"
	"fmt"
	"io"
)

type lzoReader struct {
	data []byte
	buf  *bytes.Reader
	done bool
}

// LzoNewReader creates a new LZO decompressor reader
func LzoNewReader(r io.Reader) (io.ReadCloser, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	decompressed, err := lzoDecompress(data)
	if err != nil {
		return nil, fmt.Errorf("lzo decompress: %w", err)
	}

	return &lzoReader{
		data: decompressed,
		buf:  bytes.NewReader(decompressed),
	}, nil
}

func (r *lzoReader) Read(p []byte) (int, error) {
	return r.buf.Read(p)
}

func (r *lzoReader) Close() error {
	return nil
}

// lzoDecompress implements LZO1X-1 decompression
func lzoDecompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}

	dst := make([]byte, 0, len(src)*3)
	ip := 0

	if ip >= len(src) {
		return dst, nil
	}

	// First byte determines initial literal run
	t := int(src[ip])
	ip++

	if t > 17 {
		count := t - 17
		for i := 0; i < count && ip < len(src); i++ {
			dst = append(dst, src[ip])
			ip++
		}
		if ip >= len(src) {
			return dst, nil
		}
		t = int(src[ip])
		ip++
	}

	for {
		if t >= 64 { // Match: length 3-8, offset 1-2048
			length := 1 + (t>>2)&7
			if ip >= len(src) {
				break
			}
			offset := (t >> 5) << 8
			offset += int(src[ip])
			ip++
			offset += 1

			pos := len(dst) - offset
			if pos < 0 {
				break
			}
			for i := 0; i <= length; i++ {
				if pos+i >= len(dst) {
					break
				}
				dst = append(dst, dst[pos+i])
			}
		} else if t >= 32 { // Match: length 2+, offset 1-16384
			length := t & 31
			if length == 0 {
				for ip < len(src) && src[ip] == 0 {
					length += 255
					ip++
				}
				if ip >= len(src) {
					break
				}
				length += 31 + int(src[ip])
				ip++
			}
			if ip+1 >= len(src) {
				break
			}
			offset := (int(src[ip]) | int(src[ip+1])<<8) >> 2
			ip += 2
			offset += 1

			pos := len(dst) - offset
			if pos < 0 {
				break
			}
			for i := 0; i < length+2; i++ {
				if pos+i >= len(dst) {
					break
				}
				dst = append(dst, dst[pos+i])
			}
		} else if t >= 16 { // Match or end marker
			length := t & 7
			if length == 0 {
				for ip < len(src) && src[ip] == 0 {
					length += 255
					ip++
				}
				if ip >= len(src) {
					break
				}
				length += 7 + int(src[ip])
				ip++
			}
			if ip+1 >= len(src) {
				break
			}
			offset := (int(src[ip]) | int(src[ip+1])<<8) >> 2
			ip += 2
			if offset == 0 {
				break
			} // End marker
			offset += 0x4000

			pos := len(dst) - offset
			if pos < 0 {
				break
			}
			for i := 0; i < length+2; i++ {
				if pos+i >= len(dst) {
					break
				}
				dst = append(dst, dst[pos+i])
			}
		} else { // Literal + short match
			if ip >= len(src) {
				break
			}
			offset := (t >> 2) << 8
			offset += int(src[ip])
			ip++
			offset += 1

			pos := len(dst) - offset
			if pos < 0 {
				break
			}
			dst = append(dst, dst[pos])
			if pos+1 < len(dst) {
				dst = append(dst, dst[pos+1])
			}
		}

		// Literal bytes after match
		if ip >= len(src) {
			break
		}
		t = int(src[ip])
		ip++
		if t < 16 {
			count := t
			if t == 0 {
				for ip < len(src) && src[ip] == 0 {
					count += 255
					ip++
				}
				if ip >= len(src) {
					break
				}
				count = int(src[ip]) + 15 + 3
				ip++
			} else {
				count = t
			}
			for i := 0; i < count && ip < len(src); i++ {
				dst = append(dst, src[ip])
				ip++
			}
			if ip >= len(src) {
				break
			}
			t = int(src[ip])
			ip++
		}
	}

	return dst, nil
}
