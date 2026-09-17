#!/usr/bin/env bash
set -euo pipefail

if [[ "${ROLE:-}" != "client" ]]; then
  echo "Phantom's QUIC interop endpoint supports only the client role" >&2
  exit 1
fi

/setup.sh
/wait-for-it.sh sim:57832 -s -t 30
exec /usr/local/bin/quic-interop-client
