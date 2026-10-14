# Enterprise proxy authentication investigation

Investigation on 2026-10-14. This is a proposed contract, not an implemented
authentication API. Digest delivery remains a separate obligation.

## Primary sources and peer API

- [Microsoft MS-NTHT, revision 13.0, 2024-04-23](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ntht/f09cf6e1-529e-403b-a8a5-7368ee096a6a)
  describes NTLM over HTTP and excludes Kerberos from that protocol variant.
- [Microsoft's NTLM proxy CONNECT example](https://learn.microsoft.com/en-us/openspecs/office_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a)
  shows a 407 exchange, reconnect after the initial anonymous connection
  closes, and the NTLM challenge/response on the persistent proxy connection.
- [MS-N2HT persistence rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-n2ht/c37e59c4-4252-4626-8121-957504c52cbc)
  distinguish persistent and per-request authentication. These are origin
  rules; a proxy implementation still needs a separately proved contract.
- [RFC 4559](https://www.rfc-editor.org/rfc/rfc4559.html) describes SPNEGO
  origin authentication, final tokens, mutual authentication and service
  names. It expressly excludes proxy authentication. It cannot alone
  establish a Negotiate proxy implementation.
- [libcurl CURLOPT_PROXYAUTH](https://curl.se/libcurl/c/CURLOPT_PROXYAUTH.html)
  selects proxy mechanisms explicitly. Its peer implementation supports
  separate NTLM and Negotiate choices, with build-dependent capability.
- [curl's authentication capability selection](https://github.com/curl/curl/blob/master/lib/setopt.c)
  returns NOT_BUILT_IN when the requested set leaves no compiled mechanism;
  SPNEGO requires GSS-API or SSPI. The inspected URL is moving source, not a
  pinned executable or interoperability measurement.
- [InitializeSecurityContext for Negotiate](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--negotiate)
  uses opaque tokens, continuation statuses and caller-checked final context
  attributes. Partial contexts must be released when policy is unmet.
- [Microsoft's extended-protection client procedure](https://learn.microsoft.com/en-us/windows/win32/secauthn/epa-support-in-service)
  passes TLS channel bindings into InitializeSecurityContext. Phantom uses
  BoringSSL rather than Schannel; extracting a matching binding therefore
  requires a proved backend adapter, not a copied Schannel call sequence.

## Mechanism contracts

| Mechanism | Proposed explicit choice | Platform boundary | Current result |
| --- | --- | --- | --- |
| NTLM | NTLMv2 only, no LM/NTLMv1 downgrade | Windows SSPI; any portable implementation requires separate review and peer proof | Feasible connection-bound design; no implementation or peer acceptance |
| Negotiate | SPNEGO with an explicit permitted-mechanism policy | Windows SSPI or a discovered Unix GSS-API provider | Feasible provider-backed design; provider capabilities and proxy behavior unverified |
| Kerberos | Kerberos-only policy within Negotiate, rejecting an NTLM result | Windows SSPI or Unix GSS-API, with a usable credential cache/KDC | Requires a controlled realm and proxy; no realm or acceptance experiment yet |

The provider must report the selected mechanism and final attributes. A
Kerberos-only choice cannot silently become NTLM, Basic or Digest. Ambient
credentials need a distinct caller opt-in; parsing a proxy URI cannot select
the logged-in account. Token generation has no access to origin credentials.

## Connection and identity contract

Initially qualify HTTP/1.1 proxy CONNECT and plaintext forwarding separately.
Do not silently downgrade an HTTP/2 proxy route. Until a connection-bound
multiplexing contract is implemented and peer-verified, reject enterprise
authentication on that route before proxy I/O.

An authentication context belongs to its proxy connection and credential
identity. Scope it by endpoint, target service principal, selected mechanism,
credential provider, policy and authenticated outer TLS. Never reuse the
context across proxy identities or pooled connections for a different
credential. A redirect that changes proxy identity, credentials, policy or
outer TLS scope cannot carry that context onward. A redirect through the
same scoped proxy connection may preserve its proxy context. A reconnect
starts a fresh context and exchange.

Use the caller's configured proxy hostname for service identity. Define an
explicit override for a service principal when deployment requires one.
DNS answers, reverse lookup and the tunneled origin must not silently rewrite
that identity. Bind HTTPS proxy authentication to the authenticated outer
TLS channel. An origin TLS certificate cannot supply the proxy binding.

A request deadline owns all continuation rounds and reconnects. Set named
token-size and round bounds before implementation, based on supported provider
limits and controlled-peer evidence. Decode token framing strictly and
zeroize transient secrets. Keep tokens and credential handles out of logs.
Authenticate before transmitting an unreplayable upload where possible;
return a typed replay failure otherwise. Cancellation releases provider
buffers, context handles and the challenged connection deterministically.

## Feasibility work required before exposure

Read-only local capability probes retained in
`f4-windows-curl-capabilities.log` and `f4-wsl-auth-capabilities.log`:

- Windows system curl 8.21.0 advertises SSPI, SPNEGO and Kerberos. Its feature
  list does not advertise NTLM. This is a peer build capability report,
  not a successful authentication exchange or an OS provider inventory.
- Ubuntu 24.04 curl 8.5.0 advertises GSS-API, SPNEGO, Kerberos and NTLM.
  `kinit` and `krb5-config` were absent from PATH; pkg-config could not
  resolve `krb5-gssapi`. The combined probe returned 1. This establishes
  missing development/discovery commands on that path, not the absence of
  a runtime library, credential cache, alternate installation or realm.

No ambient credentials were requested or transmitted. No packages, local
accounts, trust roots or domain settings were changed.

Repository unsafe rules currently permit only the QUIC backend and socket
FFI boundaries. A Windows SSPI implementation therefore needs a new documented
and audited private boundary before code is admitted. Unix needs an explicit
GSS-API implementation/linking contract and capability detection. An installed
provider is not proof that its NTLM mechanism or Kerberos realm is available.

Required owned peers cover multi-round success, malformed and oversized
tokens, final-token mutual-auth failure, exhausted rounds, cancellation,
connection close between rounds, cross-credential pool reuse, channel-binding
mismatch and non-replayable uploads. Windows SSPI and Unix GSS-API need their
own evidence. No enterprise runtime support is claimed by this investigation.

## Next

- [Proxy routes](../../guides/routes-and-proxies.md)
- [Coverage](../../reference/coverage.md)
