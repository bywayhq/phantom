// Firefox additions to the agent in socket_hooks.js. firefox_socket_hooks.py
// loads this file after socket_hooks.js as one script, so it calls that
// agent's report, hex, caller, socketKey, and attach functions. It reports
// raw values and leaves decoding to firefox_socket_hooks.py, where it is
// tested.

const FIREFOX_SOL_SOCKET = 0xffff;
const FIREFOX_SO_ERROR = 0x1007;
// addrinfo on x64: ai_flags, ai_family, ai_socktype, ai_protocol (int each),
// ai_addrlen (size_t), ai_canonname, ai_addr, ai_next.
const ADDRINFO_CANONNAME = 24;
// DNS_RECORDA on x64: pNext, pName, wType, wDataLength, Flags, dwTtl.
const DNS_RECORD_TYPE = 16;
const DNS_RECORD_FLAGS = 20;
const DNS_RECORD_TTL = 24;

const firefoxHooked = new Set();
// When set, a getaddrinfo call for `rewriteHost` resolves `rewriteTo`
// instead, and the answer's canonical name is dropped so the browser's TTL
// lookup still names `rewriteHost`.
let rewriteHost = null;
let rewriteTo = null;

recv("firefox-config", (message) => {
  rewriteHost = message.rewrite_host || null;
  rewriteTo = message.rewrite_to || null;
  report("firefox-config", { rewrite_host: rewriteHost, rewrite_to: rewriteTo });
});

function hookFirefoxWinsock(module) {
  attach(module, "shutdown", {
    onEnter(args) {
      report("shutdown", {
        socket: socketKey(args[0]),
        how: args[1].toInt32(),
        caller: caller(this),
      });
    },
  });
  // NSPR reads SO_ERROR to learn how a non-blocking connect ended, so this
  // is when each attempt succeeded or failed.
  attach(module, "getsockopt", {
    onEnter(args) {
      this.wanted =
        args[1].toInt32() === FIREFOX_SOL_SOCKET && args[2].toInt32() === FIREFOX_SO_ERROR;
      this.key = socketKey(args[0]);
      this.value = args[3];
    },
    onLeave(retval) {
      if (this.wanted && retval.toInt32() === 0) {
        report("socket-error", { socket: this.key, value: this.value.readS32() });
      }
    },
  });
  attach(module, "getaddrinfo", {
    onEnter(args) {
      this.name = args[0].isNull() ? null : args[0].readAnsiString();
      const hints = args[2];
      const fields = { function: "getaddrinfo", host: this.name, caller: caller(this) };
      if (!hints.isNull()) {
        fields.flags = hints.readS32();
        fields.family = hints.add(4).readS32();
        fields.socktype = hints.add(8).readS32();
        fields.protocol = hints.add(12).readS32();
      }
      report("resolve-hints", fields);
      this.rewritten = false;
      if (rewriteHost !== null && this.name === rewriteHost) {
        // Kept on `this` so the string outlives the call.
        this.replacement = Memory.allocAnsiString(rewriteTo);
        args[0] = this.replacement;
        this.rewritten = true;
        this.result = args[3];
        report("resolve-rewritten", { host: this.name, to: rewriteTo });
      }
    },
    onLeave(retval) {
      if (this.rewritten && retval.toInt32() === 0 && !this.result.isNull()) {
        const first = this.result.readPointer();
        if (!first.isNull()) {
          // freeaddrinfo skips a null name; the original string leaks.
          first.add(ADDRINFO_CANONNAME).writePointer(NULL);
        }
      }
    },
  });
}

function dnsRecords(first) {
  const records = [];
  let entry = first;
  while (!entry.isNull() && records.length < 32) {
    records.push([
      entry.add(DNS_RECORD_TYPE).readU16(),
      entry.add(DNS_RECORD_FLAGS).readU32() & 0x3,
      entry.add(DNS_RECORD_TTL).readU32(),
    ]);
    entry = entry.readPointer();
  }
  return records;
}

function hookFirefoxDnsApi(module) {
  attach(module, "DnsQuery_A", {
    onEnter(args) {
      this.host = args[0].isNull() ? null : args[0].readAnsiString();
      this.type = args[1].toInt32() & 0xffff;
      this.results = args[4];
      report("dnsquery", {
        function: "DnsQuery_A",
        host: this.host,
        query_type: this.type,
        options: args[2].toUInt32(),
        caller: caller(this),
      });
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const fields = { function: "DnsQuery_A", host: this.host, query_type: this.type, status };
      fields.records = status === 0 && !this.results.isNull()
        ? dnsRecords(this.results.readPointer())
        : [];
      report("dnsquery-return", fields);
    },
  });
}

function hookFirefoxModule(module) {
  const name = module.name.toLowerCase();
  if (firefoxHooked.has(name)) {
    return;
  }
  if (name === "ws2_32.dll") {
    firefoxHooked.add(name);
    hookFirefoxWinsock(module);
  } else if (name === "dnsapi.dll") {
    firefoxHooked.add(name);
    hookFirefoxDnsApi(module);
  }
}

for (const name of ["ws2_32.dll", "dnsapi.dll"]) {
  const module = Process.findModuleByName(name);
  if (module !== null) {
    hookFirefoxModule(module);
  }
}
Process.attachModuleObserver({ onAdded: hookFirefoxModule });
report("firefox-ready", { pid: Process.id });
