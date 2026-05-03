# go-squashfs

Pure Go SquashFS reader **and writer** for firmware analysis. Zero external dependencies.

## Features

- **Pure Go** — works on Linux, macOS, Windows
- **Read**: open, list, extract SquashFS 4.0 images
- **Write**: create SquashFS images from directories
- **Compression**: gzip, xz, lzma, lzo, lz4, zstd (all 6 types, read + write)
- **Memory-efficient**: file-backed I/O, streaming extraction
- Designed for firmware security analysis (pairs with [go-ubi](https://github.com/Nyarime/go-ubi))

## Usage

### Reading

```go
import "github.com/Nyarime/go-squashfs"

r, err := squashfs.OpenFile("rootfs.squashfs")
if err != nil { log.Fatal(err) }
defer r.Close()

fmt.Println(r.String())
// SquashFS v4.0 xz block=262144 inodes=1558 size=15597326

names, _ := r.ListRoot()
// [bin dev etc lib mnt overlay proc rom root sbin sys tmp usr var www]

count, _ := r.ExtractTo("./output")
fmt.Printf("Extracted %d files\n", count)
```

### Writing

```go
w := squashfs.NewWriter()
w.SetCompressor(squashfs.CompXZ) // or CompGzip, CompLZMA, CompLZO, CompLZ4, CompZstd
err := w.CreateFromDir("./rootfs", "output.squashfs")
```

### Compression support

| Type | ID | Read | Write |
|------|-----|------|-------|
| gzip | 1  | ✅   | ✅    |
| lzma | 2  | ✅   | ✅    |
| lzo  | 3  | ✅   | ✅    |
| xz   | 4  | ✅   | ✅    |
| lz4  | 5  | ✅   | ✅    |
| zstd | 6  | ✅   | ✅    |

## Install

```bash
go get github.com/Nyarime/go-squashfs@latest
```

## Status

- ✅ Superblock parsing
- ✅ Metadata block decompression (all 6 compressors)
- ✅ Directory listing and traversal
- ✅ Full file extraction with permissions
- ✅ Data block reading (regular files)
- ✅ Fragment table support
- ✅ Symlink support
- ✅ Extended attributes (xattr)
- ✅ SquashFS image creation (writer)
- ✅ Memory-efficient streaming I/O

## Related

- [go-ubi](https://github.com/Nyarime/go-ubi) — Pure Go UBI/UBIFS reader
- [Nyarc](https://nyarc.bbie.net) — Firmware security audit platform
- [nyarc-python](https://github.com/Nyarime/nyarc-python) — Python SDK

## License

MIT

## Credits

Built by [Naixi Networks](https://naixi.net) for the [Nyarc](https://nyarc.bbie.net) firmware security audit tool.
