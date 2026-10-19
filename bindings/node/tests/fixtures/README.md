The certificate and private key are public, test-only loopback fixtures. The
certificate covers `localhost` and `127.0.0.1`, from 2020 through 2040. Tests
explicitly add its DER certificate to the native client's trust roots.
