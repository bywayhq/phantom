# Packaged capture fixtures

These byte-identical copies let the packaged testkit run its fixture tests
without a checkout of the whole repository. The source captures stay under
the repository's root `fixtures/` directory. Update a copy only with its
source, then verify its SHA-256.

| Package-relative path | Source path | SHA-256 |
| --- | --- | --- |
| `tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt` | `fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt` | `ef45aa180204c4c2e7c1b65f77967971c2a17296c15763e03392336575f8ba86` |
| `tls/firefox/157.0/windows-11-26200/client-hello.txt` | `fixtures/tls/firefox/157.0/windows-11-26200/client-hello.txt` | `12e4d0fd942f055d2152fab0fa6c492d647e8ac8bf6613620b2c1e7a6c8b76bd` |
| `http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-1.txt` | `fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-1.txt` | `9085b2a9a9d2a0e2a9f2ab286981442f7774585080f9104317258cf89a51edcf` |
| `http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-2.txt` | `fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-2.txt` | `a1391bdc5e7f1641c26dc44faa59fcd77a85b85037cf65e1112755de85ef2062` |

The package's `.gitattributes` keeps all fixture bytes unchanged across
checkouts. The tests select complete retained observations and reject
missing or malformed data.

## Next

- [HTTP/1 provenance](http1/README.md): request-head capture metadata and
  hashes.
- [Testkit](../README.md): bounded capture and comparison APIs.
