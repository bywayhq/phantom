/*
 * SDK-owned libresolv state and optional dnsinfo witness. Primary ABI sources:
 * Apple configd-1405.120.5 dnsinfo.h (DNSINFO_VERSION 20170629), libresolv-96
 * resolv.h, and Chromium 154.0.8037.58 dns_config_watcher_mac.cc.
 * Only the common dnsinfo prefixes are projected; no copied Apple implementation.
 */
#include "macos_dns.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <notify.h>
#include <poll.h>
#include <resolv.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The audited target is Darwin's 64-bit ABI, not an inferred 32-bit layout. */
_Static_assert(sizeof(void *) == 8, "dnsinfo requires the audited 64-bit ABI");
_Static_assert(MAXNS == 3 && MAXDNSRCH == 6, "review changed resolver capacities");
_Static_assert(sizeof(struct phantom_dns_address) == 32, "address projection ABI");
_Static_assert(sizeof(struct phantom_dns_settings) == 1664, "settings projection ABI");

#pragma pack(push, 4)
struct dns_resolver_prefix {
    union { const char *pointer; uint64_t padding; } domain;
    int32_t n_nameserver;
    union { void *pointer; uint64_t padding; } nameserver;
    uint16_t port;
    int32_t n_search;
    union { void *pointer; uint64_t padding; } search;
    int32_t n_sortaddr;
    union { void *pointer; uint64_t padding; } sortaddr;
    union { const char *pointer; uint64_t padding; } options;
};
struct dns_config_prefix {
    int32_t n_resolver;
    union { const void *pointer; uint64_t padding; } resolver;
};
#pragma pack(pop)

_Static_assert(offsetof(struct dns_config_prefix, resolver) == 4, "dnsinfo list ABI");
_Static_assert(offsetof(struct dns_resolver_prefix, n_nameserver) == 8, "dnsinfo count ABI");
_Static_assert(offsetof(struct dns_resolver_prefix, options) == 48, "dnsinfo option ABI");
_Static_assert(sizeof(struct dns_config_prefix) == 12, "dnsinfo config prefix ABI");
_Static_assert(sizeof(struct dns_resolver_prefix) == 56, "dnsinfo resolver prefix ABI");

struct dns_api {
    void *library;
    const char *(*key)(void);
    void *(*copy)(void);
    void (*release)(void *);
};

static void api_close(struct dns_api *api) {
    if (api->library != NULL) dlclose(api->library);
    memset(api, 0, sizeof(*api));
}

static uint32_t api_open(struct dns_api *api) {
    memset(api, 0, sizeof(*api));
    api->library = dlopen("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_NOLOAD);
    if (api->library == NULL) return PHANTOM_DNS_UNAVAILABLE;
    /* POSIX dlsym permits these function-pointer conversions. Never load from
     * a caller-specified path, or invoke a partial function table. */
    api->key = (const char *(*)(void))dlsym(api->library, "dns_configuration_notify_key");
    api->copy = (void *(*)(void))dlsym(api->library, "dns_configuration_copy");
    api->release = (void (*)(void *))dlsym(api->library, "dns_configuration_free");
    if (api->key == NULL || api->copy == NULL || api->release == NULL) {
        api_close(api);
        return PHANTOM_DNS_UNAVAILABLE;
    }
    return PHANTOM_DNS_OK;
}

static int is_mdns(const char *options) {
    /* Short-circuit at the first mismatch/NUL, without an unbounded strlen. */
    return options != NULL && options[0] == 'm' && options[1] == 'd' &&
           options[2] == 'n' && options[3] == 's' && options[4] == '\0';
}

static uint32_t resolver_eligibility(const void *config, uint32_t *ineligible) {
    int32_t count;
    const void *list;
    /* OS allocation contract: config and its graph live until matching free.
     * Packed fields AND pointer-array elements may have only 4-byte alignment. */
    memcpy(&count, config, sizeof(count));
    memcpy(&list, (const uint8_t *)config + 4, sizeof(list));
    /* Current Apple expanded graph is at most 1MiB. This is a defensive resource
     * bound, not a browser/public API resolver limit or pointer-validity proof. */
    if (count < 0 || count > 131072 || (count != 0 && list == NULL))
        return PHANTOM_DNS_INVALID;
    unsigned relevant = 0;
    for (int32_t i = 0; i < count; ++i) {
        const void *resolver;
        int32_t nameservers;
        const char *options;
        memcpy(&resolver, (const uint8_t *)list + (size_t)i * sizeof(void *),
               sizeof(resolver));
        if (resolver == NULL) return PHANTOM_DNS_INVALID;
        memcpy(&nameservers, (const uint8_t *)resolver + 8, sizeof(nameservers));
        if (nameservers < 0) return PHANTOM_DNS_INVALID;
        if (nameservers == 0) continue;
        memcpy(&options, (const uint8_t *)resolver + 48, sizeof(options));
        if (is_mdns(options)) continue;
        if (++relevant > 1) {
            *ineligible |= PHANTOM_DNS_RESOLVERS;
            break;
        }
    }
    return PHANTOM_DNS_OK;
}

static uint32_t project_state(res_state state, struct phantom_dns_settings *out) {
    union res_sockaddr_union servers[MAXNS];
    memset(servers, 0, sizeof(servers));
    if (!(state->options & RES_INIT) || state->nscount < 0 || state->nscount > MAXNS)
        return PHANTOM_DNS_INVALID;
    int count = res_getservers(state, servers, MAXNS);
    if (count <= 0 || count > MAXNS || count != state->nscount ||
        state->retry < 0 || state->retrans < 0)
        return PHANTOM_DNS_INVALID;
    out->nameserver_count = (uint32_t)count;
    for (int i = 0; i < count; ++i) {
        struct phantom_dns_address *address = &out->nameservers[i];
        if (servers[i].sin.sin_family == AF_INET &&
            servers[i].sin.sin_len >= sizeof(struct sockaddr_in)) {
            address->family = 4;
            address->port = ntohs(servers[i].sin.sin_port);
            memcpy(address->address, &servers[i].sin.sin_addr, 4);
        } else if (servers[i].sin6.sin6_family == AF_INET6 &&
                   servers[i].sin6.sin6_len >= sizeof(struct sockaddr_in6)) {
            address->family = 6;
            address->port = ntohs(servers[i].sin6.sin6_port);
            address->scope = servers[i].sin6.sin6_scope_id;
            address->flow = servers[i].sin6.sin6_flowinfo;
            memcpy(address->address, &servers[i].sin6.sin6_addr, 16);
        } else return PHANTOM_DNS_INVALID;
    }
    for (unsigned i = 0; i < MAXDNSRCH && state->dnsrch[i] != NULL; ++i) {
        uintptr_t start = (uintptr_t)state->defdname;
        uintptr_t address = (uintptr_t)state->dnsrch[i];
        /* The inspected Darwin initializer stores search strings in defdname.
         * Reject a changed representation rather than scan unknown storage. */
        if (address < start || address - start >= sizeof(state->defdname))
            return PHANTOM_DNS_INVALID;
        size_t available = sizeof(state->defdname) - (size_t)(address - start);
        const char *end = memchr(state->dnsrch[i], '\0', available);
        if (end == NULL) return PHANTOM_DNS_INVALID;
        size_t length = (size_t)(end - state->dnsrch[i]);
        memcpy(out->search[i], state->dnsrch[i], length);
        ++out->search_count;
    }
    if (state->dnsrch[MAXDNSRCH] != NULL) return PHANTOM_DNS_INVALID;
    out->ndots = state->ndots; /* SDK C bitfield access, never guessed Rust ABI. */
    out->attempts = (uint32_t)state->retry;
    out->retrans_seconds = (uint32_t)state->retrans;
#ifdef RES_ROTATE
    out->rotate = (state->options & RES_ROTATE) != 0;
#endif
    unsigned long required = RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
    unsigned long unsupported = RES_USEVC | RES_IGNTC;
#ifdef RES_USE_DNSSEC
    unsupported |= RES_USE_DNSSEC;
#endif
    /* Conservatively keep BOTH causes; Chromium's Mac check overwrites its
     * earlier unsupported-options boolean. Do not claim assignment parity. */
    if ((state->options & required) != required || (state->options & unsupported))
        out->ineligible |= PHANTOM_DNS_OPTIONS;
    return PHANTOM_DNS_OK;
}

uint32_t phantom_macos_dns_read(struct phantom_dns_settings *out, uint32_t *detail) {
    if (out == NULL || detail == NULL) return PHANTOM_DNS_INVALID;
    *detail = 0;
    memset(out, 0, sizeof(*out));
    out->abi = PHANTOM_DNS_ABI;
    struct dns_api api;
    uint32_t status = api_open(&api);
    if (status != PHANTOM_DNS_OK) return status;
    void *config = api.copy();
    if (config == NULL) {
        api_close(&api);
        return PHANTOM_DNS_UNAVAILABLE;
    }
    status = resolver_eligibility(config, &out->ineligible);
    api.release(config); /* Exact allocator pair, including every parse failure. */
    if (status == PHANTOM_DNS_OK) {
        struct __res_state state;
        memset(&state, 0, sizeof(state));
        int initialized = res_ninit(&state);
        if (initialized == 0) status = project_state(&state, out);
        else { status = PHANTOM_DNS_NATIVE; *detail = (uint32_t)errno; }
        /* Darwin initializes cleanup fields before a returned failure;
         * Chromium ScopedResState likewise always destroys after its attempt. */
        res_ndestroy(&state);
    }
    api_close(&api);
    return status;
}

struct dns_watch {
    struct dns_api api;
    int fd;
    int token;
};

uint32_t phantom_macos_dns_watch_start(void **out, uint32_t *detail) {
    if (out == NULL || detail == NULL) return PHANTOM_DNS_INVALID;
    *out = NULL; *detail = 0;
    struct dns_watch *watch = calloc(1, sizeof(*watch));
    if (watch == NULL) { *detail = ENOMEM; return PHANTOM_DNS_NATIVE; }
    watch->fd = -1; watch->token = NOTIFY_TOKEN_INVALID;
    uint32_t status = api_open(&watch->api);
    if (status != PHANTOM_DNS_OK) { free(watch); return status; }
    const char *key = watch->api.key();
    if (key == NULL || key[0] == '\0') status = PHANTOM_DNS_UNAVAILABLE;
    else {
        *detail = notify_register_file_descriptor(key, &watch->fd, 0, &watch->token);
        if (*detail != NOTIFY_STATUS_OK) status = PHANTOM_DNS_NATIVE;
    }
    if (status != PHANTOM_DNS_OK) { api_close(&watch->api); free(watch); return status; }
    /* Transfer ownership even when descriptor setup fails, so the caller can
     * retain both this failure and a subsequent cancellation failure. */
    *out = watch;
    int descriptor_flags = fcntl(watch->fd, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(watch->fd, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
        *detail = (uint32_t)errno;
        return PHANTOM_DNS_NATIVE;
    }
    return PHANTOM_DNS_OK;
}

uint32_t phantom_macos_dns_watch_check(void *owner, uint32_t *changed,
                                     uint32_t *detail) {
    if (owner == NULL || changed == NULL || detail == NULL) return PHANTOM_DNS_INVALID;
    struct dns_watch *watch = owner;
    int check = 0;
    *detail = notify_check(watch->token, &check);
    if (*detail != NOTIFY_STATUS_OK) return PHANTOM_DNS_NATIVE;
    if (check != 0 && check != 1) return PHANTOM_DNS_INVALID;
    *changed = (uint32_t)check;
    return PHANTOM_DNS_OK;
}

uint32_t phantom_macos_dns_watch_wait(void *owner, int control, uint32_t *event,
                                    uint32_t *detail) {
    if (owner == NULL || control < 0 || event == NULL || detail == NULL)
        return PHANTOM_DNS_INVALID;
    struct dns_watch *watch = owner;
    struct pollfd fds[2] = {{control, POLLIN, 0}, {watch->fd, POLLIN, 0}};
    int ready;
    do { ready = poll(fds, 2, -1); } while (ready < 0 && errno == EINTR);
    if (ready < 0) { *detail = (uint32_t)errno; return PHANTOM_DNS_NATIVE; }
    if (fds[0].revents & (POLLIN | POLLHUP)) {
        uint8_t byte;
        ssize_t count;
        do { count = read(control, &byte, 1); } while (count < 0 && errno == EINTR);
        if (count < 0) { *detail = (uint32_t)errno; return PHANTOM_DNS_NATIVE; }
        *event = count == 0 ? 0 : 2;
        return PHANTOM_DNS_OK;
    }
    if (fds[0].revents & (POLLERR | POLLNVAL)) return PHANTOM_DNS_INVALID;
    if (fds[1].revents & POLLIN) {
        int token;
        ssize_t count;
        do { count = read(watch->fd, &token, sizeof(token)); }
        while (count < 0 && errno == EINTR);
        if (count != (ssize_t)sizeof(token)) {
            *detail = count < 0 ? (uint32_t)errno : 0;
            return PHANTOM_DNS_NATIVE;
        }
        /* No token comparison: Apple notification delivery has historical
         * byte-order differences (same rule as Chromium NotifyWatcherMac). */
        *event = 1;
        return PHANTOM_DNS_OK;
    }
    return PHANTOM_DNS_INVALID;
}

uint32_t phantom_macos_dns_watch_close(void *owner, uint32_t *detail) {
    if (owner == NULL || detail == NULL) return PHANTOM_DNS_INVALID;
    struct dns_watch *watch = owner;
    *detail = notify_cancel(watch->token); /* Also owns closing watch->fd. */
    /* A failed cancel may leave this one native registration alive. It has no
     * callback/context pointer into this allocation. Do not manually close its
     * fd: the library still owns it. Keep the exact failure in Rust state. */
    api_close(&watch->api);
    free(watch);
    return *detail == NOTIFY_STATUS_OK ? PHANTOM_DNS_OK : PHANTOM_DNS_NATIVE;
}
