# Changelog

## Unreleased

- Add `Client::close_idle_connections` to release idle origin and proxy
  connections while retaining active work, TLS tickets and session state.
- Rebuild the user documentation around docs.rs: a short README, an API
  overview, and four guides for getting started, browser profiles, requests
  and responses, and proxies.
- Remove the old repository documentation tree and its obsolete navigation.
- Add a bounded JSON example and update the first-request, request-template,
  and proxy examples to use the composed browser profiles.
