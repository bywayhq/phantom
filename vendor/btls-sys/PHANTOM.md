# Phantom vendor notes: btls-sys

This package contains the native TLS source used by Phantom. Refresh it with
`scripts/ci/stage-btls-sys.sh DESTINATION`, then compare the staged tree with
this directory. The script verifies both source archive checksums.

- Native fork: `https://github.com/bywayhq/btls`
- Native revision: `f478ea16a4b2f6ebbd221ce7cafdec10a32028eb`
- Native archive SHA-256:
  `e9c2fd9f12a995afc8adcd31b86effa9d767570d9e4e52efee68b5ffc2d626cf`
- BoringSSL revision: `f1f2556a5dfa59e147d9d47279cc3f7f8a18b433`
- BoringSSL archive SHA-256:
  `0a92d2306442146e4994409aefc1bb50d4b664750f4bdd7faf14c6b0a6a04e7e`

## Canonical changes

`patches/series` lists the packaging changes to replay on the native fork.
`publish-identity.patch` is last. It materializes workspace fields, names the
package `phantom-btls-sys`, retains the library name `btls_sys`, and changes
`links` to `phantom_boringssl`. It includes the bundled license files in the
archive. It changes no native or Rust behavior.

The other files in `patches/` are unchanged inputs from the native fork.
The build script applies them to its private BoringSSL copy. They are not
packaging patches and must not be added to `series`. All seventeen numbered
patches remain present, along with the upstream optional patches.

The full BoringSSL tree supports the existing native test runner. Cargo's
include list packages the build sources and license files. The crate needs
no submodule fetch when installed from its archive.

## Licenses and compatibility

The Rust bindings use MIT. BoringSSL and its bundled support code carry
Apache-2.0 and BSD-3-Clause terms. Original notices remain in `LICENSE-MIT`,
`deps/boringssl/LICENSE`, and the third-party license files. `NOTICE` lists
their locations. Retain these notices when redistributing native binaries.

The separate `links` value does not establish compatibility with another
BoringSSL in the same process. Symbol prefixing remains limited by the
upstream build, including its Windows and Apple restrictions. No broader
coexistence support is claimed.

## Verification

Run `scripts/ci/check-vendor.sh btls-sys` through the Cargo lock helper.
It replays and compares the complete source, then checks the native crate.
The release package check also builds from the archive on each platform.
