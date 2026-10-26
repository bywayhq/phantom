# Getting started

Send an HTTPS request using Chrome's connection settings, then read its response
with a byte limit. This guide assumes you can run a Rust program with Cargo.

## Install the build tools

Use Rust 1.88 or newer. Phantom builds BoringSSL from source, so Cargo also needs
Git, CMake, Clang with `libclang`, and a C++ compiler. The first build takes longer
than later builds.

- On Linux, install those tools with your distribution's package manager.
- On macOS, install the Xcode Command Line Tools and CMake. Make sure Clang and
  `libclang` are available to the build.
- On Windows, use the MSVC Rust toolchain. Install Visual Studio Build Tools with
  the **Desktop development with C++** workload and Windows SDK, plus Git, CMake,
  LLVM, and NASM.

On Windows, check that the shell running Cargo can find the tools:

```powershell
Get-Command git, cmake, clang, nasm
```

If LLVM or NASM is missing from `PATH`, add its installation directory and open a
new terminal. Common locations are `C:\Program Files\LLVM\bin` and
`C:\Program Files\NASM`. If bindgen cannot find `libclang`, set `LIBCLANG_PATH`
to LLVM's `bin` directory in that terminal:

```powershell
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
```

## Create a project

```console
cargo new phantom-example
cd phantom-example
```

Add these dependencies to `Cargo.toml`:

```toml
[dependencies]
phantom = { package = "phantom-http", version = "0.5" }
tokio = { version = "1", features = ["macros", "rt", "net", "time"] }
```

The published package is `phantom-http`; the dependency name above lets your code
import it as `phantom`. No optional Phantom features are needed for this request.

## Send a request

Replace `src/main.rs` with:

```no_run
use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::Client;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let client = Client::builder(profile).build()?;
    let response = client
        .get("https://example.com/")?
        .send()
        .await?;

    println!("status: {}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("body: {} bytes", body.len());
    Ok(())
}
```

Run it:

```console
cargo run
```

The program prints the HTTP status and the number of response bytes. The body
limit is 1 MiB; a larger response returns an error instead of being fully buffered.
TLS negotiates HTTP/1.1 or HTTP/2. Use
[`Client::get_with_protocol`](crate::Client::get_with_protocol) when you need
one exact protocol.

[`profile_for`](crate::profile::catalog::profile_for) selects Chrome 156's
Windows settings and page-load headers together. Choose a fetch or upload
context when needed, as shown in [Browser profiles](crate::guide::browser_profiles).

## Keep the client for later requests

Build a [`Client`](crate::Client) once and use it for multiple requests. Its
connections and TLS sessions can be reused. Cloning a client shares those pools
and its state; building another client creates separate state.

Read each response body to the end when you want its connection to remain
available for reuse. If you stop early or exceed a body limit, dropping the body
cancels the remaining read; cleanup and connection reuse depend on the protocol.
You do not need a separate close call for the client.

To stop accepting work and wait for active operations, use
[`Client::shutdown`](crate::Client::shutdown). Read response bodies through EOF
or drop them, and finish or drop WebSockets. Client clones share shutdown state.

## Restrict server public keys

Use [`ClientBuilder::server_spki_pins`](crate::ClientBuilder::server_spki_pins)
with [`ServerSpkiPins`](crate::ServerSpkiPins) when you need to accept only
specific server keys. Supply SHA-256 digests of each accepted leaf
certificate's DER SubjectPublicKeyInfo. Include both keys during rotation.
Certificate-chain and hostname verification still apply.

The policy covers every origin reached by this client, including redirects
and WebSockets. Cleartext origin requests fail. Build a separate client to
change the policy; pooled connections and imported tickets cannot acquire
a different policy.

Continue with [Making requests and handling responses](crate::guide::requests_and_responses)
for headers, uploads, JSON, streaming, and timeouts, or
[Using proxies](crate::guide::proxies) to change the route.
