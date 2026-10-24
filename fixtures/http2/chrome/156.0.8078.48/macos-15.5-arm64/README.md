# Chrome 156 idle HTTP/2 requests

Headed Chrome 156.0.8078.48 on macOS 15.5 (24F74), arm64. The browser used
three connections. The final connection carried `/b`, `/c`, `/p` and `/done`.
Its POST headers were followed by PING 1, then 100 bytes of DATA ending the
stream. The earlier Windows v1 capture remains separate.

Run from the repository root:

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  --with cryptography==50.0.1 python -m scripts.capture.http2_preface_ping \
  --browser chrome \
  --browser-path '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
  --headful --client-version 156.0.8078.48 \
  --operating-system 'macOS 15.5 24F74 arm64' \
  --output-dir target/preface-ping
```
