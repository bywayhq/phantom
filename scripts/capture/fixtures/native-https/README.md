# Native HTTPS test identity

These files belong to the loopback Firefox native-DNS capture. The leaf covers
`server.phantom.test`, `public.phantom.test` and `127.0.0.1`. Its private key is
public test material. Never use it outside captures.

`cert9.db` contains only the test CA, trusted for TLS servers. The capture
copies it into a fresh Firefox profile. It changes no machine or personal
browser trust store. The CA private key was discarded after signing the leaf.

Generated with OpenSSL 3.0.13 and Ubuntu NSS tools 3.98. Both certificates use
P-256 keys and SHA-256 signatures. They expire in October 2036. To replace
them, create a test CA and a server-auth leaf with the same names, then create
an empty NSS SQL database and import only the CA with `certutil -A -t 'C,,'`.
Retain its `cert9.db`, the CA certificate and the leaf certificate/key.
