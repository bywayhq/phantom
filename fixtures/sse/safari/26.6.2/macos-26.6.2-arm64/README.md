# Safari EventSource reconnects

Safari 26.6.2 (21624.5.1.11.3), macOS 26.6.2 (25G83), arm64.
Each headed WebDriver session received a 204 response on reconnect, then
made no further request during the three-second observation.

| Protocol | Capture | Connections |
| --- | --- | --- |
| HTTP/1.1 | [Run 39935679048](https://github.com/bywayhq/phantom/actions/runs/39935679048) | Two TCP connections |
| HTTP/2 | [Run 39939206440](https://github.com/bywayhq/phantom/actions/runs/39939206440) | One connection, streams 1/3/5 |

HTTP/2 used `127.0.0.1` and a WebDriver session certificate exception.
The retained peer certificate names `server.phantom.test`. These captures
contain request fields and reconnect timing, not a TLS browser profile.

The adjacent provenance files retain the original build, source hashes,
capabilities and cleanup results. Both captures used source `05e34c71`.

## Next

- [Run the Safari capture](../../../../../scripts/capture/SAFARI.md).
