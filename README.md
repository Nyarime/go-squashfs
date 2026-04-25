# go-squashfs

Pure Go SquashFS reader for firmware analysis. Zero external dependencies.

## Features

- **Pure Go** — works on Linux, macOS, Windows
- **Compression**: gzip, xz, lzma, lz4, zstd
- **SquashFS 4.0** format
- Designed for firmware security analysis (pairs with [go-ubi](https://github.com/Nyarime/go-ubi))

## Usage

```go
import "github.com/Nyarime/go-squashfs"

r, err := squashfs.OpenFile("rootfs.squashfs")
if err != nil { log.Fatal(err) }

fmt.Println(r.String())
// SquashFS v4.0 xz block=262144 inodes=1558 size=15597326

names, err := r.ListRoot()
// [bin dev etc lib mnt overlay proc rom root sbin sys tmp usr var www]
```

## Status

- ✅ Superblock parsing
- ✅ Metadata block decompression (gzip/xz/lzma/zstd)
- ✅ Root directory listing
- 🔧 Full file extraction (in progress)
- 🔧 Data block reading

## Related

- [go-ubi](https://github.com/Nyarime/go-ubi) — Pure Go UBI/UBIFS reader
- [Nyarc](https://nyarc.bbie.net) — Firmware security audit platform

## License

MIT
