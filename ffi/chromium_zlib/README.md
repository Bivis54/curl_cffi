# Chromium's zlib, deflate only

The files Chromium's WebSocket deflater needs, copied unchanged from
https://chromium.googlesource.com/chromium/src/third_party/zlib at revision
456ae730017b9b4bd3371927abc82627fd51feef (zlib 1.3.2 with Chromium's changes).
Chromium's deflate hashes four bytes at a time (`insert_string.h`), so it finds
other matches than canonical zlib and its output differs; compressing outgoing
WebSocket messages with it gives the frames Chrome sends, byte for byte.

`scripts/build.py` compiles `deflate.c`, `trees.c`, `zutil.c` and `adler32.c`
into the extension with `CPU_NO_SIMD` (the SIMD code paths do not change the
deflate output) and `NO_GZIP`. `chromeconf.h` renames every zlib symbol with a
`Cr_z_` prefix, so this copy does not clash with the zlib in
libcurl-impersonate.

zlib is under the zlib license (`LICENSE`), the Chromium additions under the
BSD license in `LICENSE.chromium`.
