# Zstandard fixture

`example.txt.v8.zst` and its decoded `example.txt` come unchanged from
[zstd-rs 75bc740](https://github.com/gyscos/zstd-rs/tree/75bc74045a2f6ea0439aeed7e159a266da20aac0/assets).
They exercise the standard frame format used by TLS certificate compression
([RFC 8879 section 4](https://www.rfc-editor.org/rfc/rfc8879.html#section-4)).
The upstream BSD-3-Clause license is retained in `LICENSE`.
