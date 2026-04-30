package squashfs

// Pure Go XZ compressor for SquashFS blocks.
// Produces valid XZ streams with LZMA2 filter.
// Uses "stored" LZMA2 mode (uncompressed chunks in XZ container) for reliability,
// since the primary use case is firmware repacking where validity > ratio.

import (
	"encoding/binary"
	"hash/crc32"
)

// XzCompress compresses data into a valid XZ stream using LZMA2 (stored mode).
// The output is a valid XZ file decompressible by any XZ decoder.
func XzCompress(data []byte) []byte {
	if len(data) == 0 {
		return xzCompressEmpty()
	}
	return xzCompressStored(data)
}

func xzCompressEmpty() []byte {
	var out []byte
	// Stream header
	out = append(out, xzMagic...)
	// Stream flags: check type = CRC32 (0x01)
	flags := []byte{0x00, 0x01}
	out = append(out, flags...)
	crc := crc32.ChecksumIEEE(flags)
	out = appendLE32(out, crc)

	// Index: 0 records
	out = append(out, 0x00) // index indicator
	out = append(out, 0x00) // number of records = 0
	// Pad to 4-byte alignment
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	// Index CRC32
	// CRC is over the index (from indicator byte)
	idxStart := 12 // after stream header
	idxCRC := crc32.ChecksumIEEE(out[idxStart:])
	out = appendLE32(out, idxCRC)

	// Stream footer
	out = xzAppendFooter(out, 0, flags)
	return out
}

func xzCompressStored(data []byte) []byte {
	var out []byte
	// Stream header (12 bytes)
	out = append(out, xzMagic...)
	flags := []byte{0x00, 0x01} // check type = CRC32
	out = append(out, flags...)
	crc := crc32.ChecksumIEEE(flags)
	out = appendLE32(out, crc)

	// Block
	blockStart := len(out)
	blockData := xzBuildStoredBlock(data)
	out = append(out, blockData...)

	// Pad block to 4-byte boundary
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}

	// Block check: CRC32 of uncompressed data
	dataCRC := crc32.ChecksumIEEE(data)
	out = appendLE32(out, dataCRC)

	blockEnd := len(out)
	unpaddedSize := blockEnd - blockStart - (blockEnd-blockStart-len(blockData))%4
	// Actually: unpadded size = block header + compressed data + check (no padding)
	// Let me recalculate properly
	unpaddedSize = len(blockData) + 4 // blockData + 4 bytes CRC32

	// Index
	idxStart := len(out)
	out = append(out, 0x00) // index indicator
	out = append(out, 0x01) // 1 record
	out = append(out, encodeMultiByte(uint64(unpaddedSize))...)
	out = append(out, encodeMultiByte(uint64(len(data)))...)
	// Pad to 4-byte alignment
	idxSoFar := len(out) - idxStart
	for idxSoFar%4 != 0 {
		out = append(out, 0x00)
		idxSoFar++
	}
	// Index CRC32
	idxCRC := crc32.ChecksumIEEE(out[idxStart:])
	out = appendLE32(out, idxCRC)

	// Backward size = (index size / 4) - 1, where index size includes padding + CRC
	indexSize := len(out) - idxStart
	out = xzAppendFooter(out, indexSize, flags)

	return out
}

// xzBuildStoredBlock creates an XZ block with LZMA2 uncompressed chunks.
func xzBuildStoredBlock(data []byte) []byte {
	// LZMA2 filter properties: dictionary size byte
	// Use dict size = 2^23 = 8MB (byte value = 24: (24/2 - 11) => 2^23)
	// dictByte 24 => dictSize = 2 << (24/2 + 11) = 2 << 23 = 16MB. Let's use 0x18 (24).
	// Actually for stored mode, dict size doesn't matter much. Use 0x17 (23) = 2<<(11+11) = 4MB
	dictByte := byte(0x18) // 8MB dict

	// Block header
	var hdr []byte
	blockFlags := byte(0x00) // 1 filter, no compressed/uncompressed size
	blockFlags |= 0x00       // number of filters - 1 = 0 (1 filter)
	hdr = append(hdr, blockFlags)

	// Filter: LZMA2 (ID=0x21), properties size=1
	hdr = append(hdr, 0x21)       // filter ID
	hdr = append(hdr, 0x01)       // properties size
	hdr = append(hdr, dictByte)   // dict size byte

	// Pad header to multiple of 4 (including size byte)
	// Header size = 1 (size byte) + len(hdr) + padding + 4 (CRC)
	// Total must be multiple of 4
	totalWithoutCRC := 1 + len(hdr)
	padNeeded := (4 - totalWithoutCRC%4) % 4
	for i := 0; i < padNeeded; i++ {
		hdr = append(hdr, 0x00)
	}

	// Size byte: (real_header_size / 4) - 1, where real_header_size includes everything except the size byte itself
	realSize := len(hdr) + 4 // hdr + CRC32
	sizeByte := byte((realSize / 4) - 1 + 1) // the formula: (header_size_including_size_byte / 4) - 1
	// Actually: Block Header Size = (sizeByte + 1) * 4
	// We need: (sizeByte + 1) * 4 = 1 + len(hdr) + 4
	// sizeByte = (1 + len(hdr) + 4) / 4 - 1
	headerTotal := 1 + len(hdr) + 4
	// Must be multiple of 4
	if headerTotal%4 != 0 {
		extra := 4 - headerTotal%4
		for i := 0; i < extra; i++ {
			hdr = append(hdr, 0x00)
		}
		headerTotal = 1 + len(hdr) + 4
	}
	sizeByte = byte(headerTotal/4 - 1)

	var block []byte
	block = append(block, sizeByte)
	block = append(block, hdr...)
	// CRC32 of header (from size byte through padding)
	hdrCRC := crc32.ChecksumIEEE(block)
	block = appendLE32(block, hdrCRC)

	// LZMA2 data: uncompressed chunks
	block = append(block, lzma2EncodeStored(data)...)

	return block
}

// lzma2EncodeStored wraps raw data in LZMA2 uncompressed chunks.
// LZMA2 uncompressed chunk format:
//   Control byte: 0x01 (uncompressed, dict reset) or 0x02 (uncompressed, no dict reset)
//   2 bytes: data size - 1 (big-endian)
//   Raw data
// Max chunk data size: 65536 bytes
func lzma2EncodeStored(data []byte) []byte {
	const maxChunk = 65536
	var out []byte

	for i := 0; i < len(data); i += maxChunk {
		end := i + maxChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		size := len(chunk) - 1

		ctrl := byte(0x01) // uncompressed, dict reset
		if i > 0 {
			ctrl = 0x02 // uncompressed, no dict reset
		}
		out = append(out, ctrl)
		out = append(out, byte(size>>8), byte(size))
		out = append(out, chunk...)
	}

	// End marker
	out = append(out, 0x00)
	return out
}

func xzAppendFooter(out []byte, indexSize int, flags []byte) []byte {
	// Stream footer: CRC32(4) + Backward Size(4) + Stream Flags(2) + Footer Magic(2)
	backwardSize := uint32(indexSize/4 - 1)

	var footer []byte
	var bs [4]byte
	binary.LittleEndian.PutUint32(bs[:], backwardSize)
	footer = append(footer, bs[:]...)
	footer = append(footer, flags...)

	footerCRC := crc32.ChecksumIEEE(footer)
	out = appendLE32(out, footerCRC)
	out = append(out, footer...)
	out = append(out, 'Y', 'Z') // footer magic
	return out
}

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func encodeMultiByte(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}
