#!/bin/sh

exec /adapter/phantom-tls-anvil \
  --host 127.0.0.1 \
  --port 8443 \
  --server-name localhost \
  >>/output/adapter.log 2>&1
