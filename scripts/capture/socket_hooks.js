// Frida agent for socket_hooks.py: reports the Winsock and resolver calls of
// one Chromium network service process. It reports raw argument bytes and
// leaves decoding to socket_hooks.py, where it is tested.
//
// Every report is send({kind, time_ms, thread, socket?, ...}). time_ms is
// Date.now() in the hooked process; byte arguments are lowercase hex.

const MAX_BYTES = 512;
const SIO_GET_EXTENSION_FUNCTION_POINTER = 0xc8000006;
const SIO_TCP_INITIAL_RTO = 0x98000011;
// {25a207b9-ddf3-4660-8ee9-76e58c74063e} in its in-memory byte order.
const WSAID_CONNECTEX = "b907a225f3dd60468ee976e58c74063e";
const AF_INET = 2;
const AF_INET6 = 23;
const SOCK_DGRAM = 2;
const DNS_PORT = 53;

const sockets = new Map();
const hooked = new Set();
let connectExHooked = false;
// When set, SIO_TCP_INITIAL_RTO fails on IPv6 sockets, so a refused [::1]
// connect waits for Windows' SYN retransmissions (about two seconds) instead
// of failing at once. The browser's IPv4 fallback timer then shows.
let slowIpv6Refusal = false;

recv("config", (message) => {
  slowIpv6Refusal = message.slow_ipv6_refusal === true;
  report("config", { slow_ipv6_refusal: slowIpv6Refusal });
});

function hex(pointer, length) {
  if (pointer.isNull() || length <= 0) {
    return "";
  }
  const bytes = new Uint8Array(pointer.readByteArray(Math.min(length, MAX_BYTES)));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function report(kind, fields) {
  send(Object.assign({ kind, time_ms: Date.now(), thread: Process.getCurrentThreadId() }, fields));
}

// The module that made the call, so a log shows whether the browser or a
// library it loaded set an option.
function caller(context) {
  const module = Process.findModuleByAddress(context.returnAddress);
  return module === null ? "unknown" : module.name;
}

function socketKey(value) {
  return ptr(value).toString();
}

function sockaddrPort(address, length) {
  if (address.isNull() || length < 4) {
    return -1;
  }
  const family = address.readU16();
  if (family !== AF_INET && family !== AF_INET6) {
    return -1;
  }
  const port = address.add(2);
  return (port.readU8() << 8) | port.add(1).readU8();
}

function isDnsSocket(key) {
  const entry = sockets.get(key);
  return entry !== undefined && entry.type === SOCK_DGRAM && entry.peerPort === DNS_PORT;
}

function rememberPeer(key, address, length) {
  const entry = sockets.get(key) || {};
  entry.peerPort = sockaddrPort(address, length);
  sockets.set(key, entry);
}

function attach(module, name, callbacks) {
  const address = module.findExportByName(name);
  if (address === null) {
    report("hook-missing", { module: module.name, function: name });
    return;
  }
  Interceptor.attach(address, callbacks);
}

function onSocketCreated(wide) {
  return {
    onEnter(callArgs) {
      this.family = callArgs[0].toInt32();
      this.type = callArgs[1].toInt32();
      this.protocol = callArgs[2].toInt32();
      this.caller = caller(this);
    },
    onLeave(retval) {
      const key = socketKey(retval);
      sockets.set(key, { family: this.family, type: this.type, peerPort: -1 });
      report("socket", {
        socket: key,
        function: wide ? "WSASocketW" : "socket",
        family: this.family,
        type: this.type,
        protocol: this.protocol,
        caller: this.caller,
      });
    },
  };
}

function connectHook(name) {
  return {
    onEnter(args) {
      this.key = socketKey(args[0]);
      const length = args[2].toInt32();
      rememberPeer(this.key, args[1], length);
      report("connect", {
        socket: this.key,
        function: name,
        address: hex(args[1], length),
        caller: caller(this),
      });
    },
    onLeave(retval) {
      report("connect-return", {
        socket: this.key,
        function: name,
        result: retval.toInt32(),
        error: this.lastError,
      });
    },
  };
}

function hookConnectEx(address) {
  if (connectExHooked) {
    return;
  }
  connectExHooked = true;
  Interceptor.attach(address, {
    onEnter(args) {
      const key = socketKey(args[0]);
      const length = args[2].toInt32();
      rememberPeer(key, args[1], length);
      report("connect", { socket: key, function: "ConnectEx", address: hex(args[1], length) });
    },
  });
}

function sendPayload(key, buffer, length, name, to, toLength) {
  const port = to === null ? -1 : sockaddrPort(to, toLength);
  if (port !== DNS_PORT && !isDnsSocket(key)) {
    return;
  }
  report("dns-send", {
    socket: key,
    function: name,
    address: to === null ? "" : hex(to, toLength),
    payload: hex(buffer, length),
  });
}

function wsaBuffers(buffers, count) {
  // WSABUF is { ULONG len; CHAR *buf; } with the pointer at offset 8 on x64.
  const step = Process.pointerSize * 2;
  const parts = [];
  for (let i = 0; i < count; i += 1) {
    const entry = buffers.add(i * step);
    parts.push([entry.add(Process.pointerSize).readPointer(), entry.readU32()]);
  }
  return parts;
}

function addrinfoAnswers(first, extended) {
  // addrinfo, ADDRINFOW, and ADDRINFOEXW share the first 40 bytes on x64;
  // ai_next follows ai_addr in the first two and three more fields later in
  // ADDRINFOEXW.
  const nextOffset = extended ? 64 : 40;
  const answers = [];
  let entry = first;
  while (!entry.isNull() && answers.length < 32) {
    const length = entry.add(16).readU64().toNumber();
    answers.push(hex(entry.add(32).readPointer(), length));
    entry = entry.add(nextOffset).readPointer();
  }
  return answers;
}

function readName(pointer, wide) {
  if (pointer.isNull()) {
    return null;
  }
  return wide ? pointer.readUtf16String() : pointer.readAnsiString();
}

function getaddrinfoHook(name, wide, extended) {
  const resultIndex = extended ? 5 : 3;
  return {
    onEnter(args) {
      this.name = readName(args[0], wide);
      this.result = args[resultIndex];
      this.overlapped = extended ? !args[7].isNull() : false;
      report("resolve", {
        function: name,
        host: this.name,
        overlapped: this.overlapped,
        caller: caller(this),
      });
    },
    onLeave(retval) {
      const code = retval.toInt32();
      const fields = { function: name, host: this.name, result: code, answers: [] };
      if (code === 0 && !this.result.isNull()) {
        fields.answers = addrinfoAnswers(this.result.readPointer(), extended);
      }
      report("resolve-return", fields);
    },
  };
}

function hookWinsock(module) {
  attach(module, "socket", onSocketCreated(false));
  attach(module, "WSASocketW", onSocketCreated(true));
  attach(module, "connect", connectHook("connect"));
  attach(module, "WSAConnect", connectHook("WSAConnect"));
  attach(module, "bind", {
    onEnter(args) {
      report("bind", { socket: socketKey(args[0]), address: hex(args[1], args[2].toInt32()) });
    },
  });
  attach(module, "closesocket", {
    onEnter(args) {
      const key = socketKey(args[0]);
      sockets.delete(key);
      report("close", { socket: key });
    },
  });
  attach(module, "setsockopt", {
    onEnter(args) {
      report("setsockopt", {
        socket: socketKey(args[0]),
        level: args[1].toInt32(),
        option: args[2].toInt32(),
        value: hex(args[3], args[4].toInt32()),
        caller: caller(this),
      });
    },
    onLeave(retval) {
      report("setsockopt-return", { result: retval.toInt32() });
    },
  });
  attach(module, "ioctlsocket", {
    onEnter(args) {
      report("ioctlsocket", {
        socket: socketKey(args[0]),
        command: args[1].toUInt32(),
        value: hex(args[2], 4),
        caller: caller(this),
      });
    },
  });
  attach(module, "WSAIoctl", {
    onEnter(args) {
      const key = socketKey(args[0]);
      this.code = args[1].toUInt32();
      this.input = hex(args[2], args[3].toInt32());
      this.output = args[4];
      report("wsaioctl", {
        socket: key,
        code: this.code,
        input: this.input,
        caller: caller(this),
      });
      const entry = sockets.get(key);
      if (
        slowIpv6Refusal &&
        this.code === SIO_TCP_INITIAL_RTO &&
        entry !== undefined &&
        entry.family === AF_INET6
      ) {
        args[1] = ptr(0);
        report("wsaioctl-suppressed", { socket: key, code: this.code });
      }
    },
    onLeave(retval) {
      report("wsaioctl-return", { code: this.code, result: retval.toInt32() });
      if (
        this.code === SIO_GET_EXTENSION_FUNCTION_POINTER &&
        retval.toInt32() === 0 &&
        this.input === WSAID_CONNECTEX
      ) {
        hookConnectEx(this.output.readPointer());
      }
    },
  });
  attach(module, "send", {
    onEnter(args) {
      sendPayload(socketKey(args[0]), args[1], args[2].toInt32(), "send", null, 0);
    },
  });
  attach(module, "sendto", {
    onEnter(args) {
      sendPayload(
        socketKey(args[0]),
        args[1],
        args[2].toInt32(),
        "sendto",
        args[4],
        args[5].toInt32(),
      );
    },
  });
  attach(module, "WSASend", {
    onEnter(args) {
      const key = socketKey(args[0]);
      for (const [buffer, length] of wsaBuffers(args[1], args[2].toInt32())) {
        sendPayload(key, buffer, length, "WSASend", null, 0);
      }
    },
  });
  attach(module, "WSASendTo", {
    onEnter(args) {
      const key = socketKey(args[0]);
      for (const [buffer, length] of wsaBuffers(args[1], args[2].toInt32())) {
        sendPayload(key, buffer, length, "WSASendTo", args[5], args[6].toInt32());
      }
    },
  });
  attach(module, "getaddrinfo", getaddrinfoHook("getaddrinfo", false, false));
  attach(module, "GetAddrInfoW", getaddrinfoHook("GetAddrInfoW", true, false));
  attach(module, "GetAddrInfoExW", getaddrinfoHook("GetAddrInfoExW", true, true));
}

function hookDnsApi(module) {
  attach(module, "DnsQueryEx", {
    onEnter(args) {
      // DNS_QUERY_REQUEST: ULONG Version; PCWSTR QueryName; WORD QueryType.
      const request = args[0];
      report("resolve", {
        function: "DnsQueryEx",
        host: readName(request.add(8).readPointer(), true),
        query_type: request.add(16).readU16(),
        caller: caller(this),
      });
    },
  });
  attach(module, "DnsQuery_W", {
    onEnter(args) {
      report("resolve", {
        function: "DnsQuery_W",
        host: readName(args[0], true),
        query_type: args[1].toInt32() & 0xffff,
        caller: caller(this),
      });
    },
  });
}

function hookModule(module) {
  const name = module.name.toLowerCase();
  if (hooked.has(name)) {
    return;
  }
  if (name === "ws2_32.dll") {
    hooked.add(name);
    hookWinsock(module);
    report("hooked", { module: name });
  } else if (name === "dnsapi.dll") {
    hooked.add(name);
    hookDnsApi(module);
    report("hooked", { module: name });
  }
}

for (const name of ["ws2_32.dll", "dnsapi.dll"]) {
  const module = Process.findModuleByName(name);
  if (module !== null) {
    hookModule(module);
  }
}
Process.attachModuleObserver({ onAdded: hookModule });
report("ready", { pid: Process.id, arch: Process.arch });
