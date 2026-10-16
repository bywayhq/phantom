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
#include <limits.h>
#include <notify.h>
#include <poll.h>
#include <resolv.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <unistd.h>

/* The audited target is Darwin's 64-bit ABI, not an inferred 32-bit layout. */
_Static_assert(sizeof(void *) == 8, "dnsinfo requires the audited 64-bit ABI");
_Static_assert(MAXNS == 3 && MAXDNSRCH == 6, "review changed resolver capacities");
_Static_assert(PATH_MAX == 1024, "review Rust hosts-path bound against SDK");
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

/* One thread owns all descriptors below. Bounds are Phantom resource limits,
 * not Darwin/browser limits. No path, contents or hostname escapes this owner. */
#define HOSTS_BYTES (1024u * 1024u)
#define HOSTS_NODES 128u
#define HOSTS_LIVE_FDS (3u * HOSTS_NODES)
#define HOSTS_LINKS 40u
#define HOSTS_STEPS 4096u
#define EVENT_BATCH 32u
#define EVENT_ROUNDS 64u
#define VNODE_FLAGS (NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | \
                     NOTE_LINK | NOTE_RENAME | NOTE_REVOKE)

struct hosts_node { dev_t device; ino_t inode; mode_t mode; };
struct hosts_sample {
    struct hosts_node nodes[HOSTS_NODES];
    size_t node_count;
    int fds[HOSTS_NODES];
    size_t fd_count;
    uint8_t *bytes;
    size_t length;
    int present;
};
struct dns_watch {
    struct dns_api api;
    int fd[2];
    int token[2];
    int queue;
    int live[HOSTS_LIVE_FDS];
    size_t live_count;
    char *path;
    struct hosts_sample *hosts;
    char hostname[256];
    int hostname_ready;
    int pending;
};

static uint32_t native_error(uint32_t *detail, int code) {
    *detail = (uint32_t)code;
    return PHANTOM_DNS_NATIVE;
}

static int owned_close(int fd) {
    /* Never retry close: after EINTR its number may already have been reused. */
    return close(fd) == 0 ? 0 : errno;
}

static uint32_t descriptor_setup(int fd, int nonblocking, uint32_t *detail) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return native_error(detail, errno);
    if (nonblocking) {
        flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
            return native_error(detail, errno);
    }
    return PHANTOM_DNS_OK;
}

static uint32_t sample_close(struct dns_watch *watch, struct hosts_sample *sample,
                             uint32_t *detail) {
    int failure = 0;
    if (sample == NULL) return PHANTOM_DNS_OK;
    for (size_t i = 0; i < sample->fd_count; ++i) {
        int fd = sample->fds[i];
        size_t j;
        for (j = 0; j < watch->live_count && watch->live[j] != fd; ++j) {}
        if (j == watch->live_count) { if (!failure) failure = EINVAL; }
        else watch->live[j] = watch->live[--watch->live_count];
        /* Darwin close removes this fd's kevents; no detached registrations. */
        int error = owned_close(fd);
        if (error && !failure) failure = error;
    }
    free(sample->bytes);
    free(sample);
    return failure ? native_error(detail, failure) : PHANTOM_DNS_OK;
}

static uint32_t sample_node(struct hosts_sample *sample, const struct stat *st,
                            uint32_t *detail) {
    if (sample->node_count == HOSTS_NODES) return native_error(detail, E2BIG);
    struct hosts_node *node = &sample->nodes[sample->node_count++];
    node->device = st->st_dev; node->inode = st->st_ino;
    node->mode = st->st_mode & S_IFMT;
    return PHANTOM_DNS_OK;
}

/* Takes fd on every path, including registration failure. Parent watches are
 * installed BEFORE looking up children, final-file watch BEFORE reading bytes. */
static uint32_t sample_fd(struct dns_watch *watch, struct hosts_sample *sample,
                          int fd, uint32_t *detail) {
    if (sample->fd_count == HOSTS_NODES || watch->live_count == HOSTS_LIVE_FDS) {
        int error = owned_close(fd);
        return native_error(detail, error ? error : E2BIG);
    }
    sample->fds[sample->fd_count++] = fd;
    watch->live[watch->live_count++] = fd;
    uint32_t status = descriptor_setup(fd, 0, detail);
    if (status != PHANTOM_DNS_OK) return status;
    struct kevent change;
    EV_SET(&change, (uintptr_t)fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
           VNODE_FLAGS, 0, NULL);
    if (kevent(watch->queue, &change, 1, NULL, 0, NULL) < 0)
        return native_error(detail, errno);
    return PHANTOM_DNS_OK;
}

static int same_node(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT);
}

static uint32_t sample_bytes(struct hosts_sample *sample, int fd, uint32_t *detail) {
    sample->bytes = malloc(HOSTS_BYTES + 1u);
    if (sample->bytes == NULL) return native_error(detail, ENOMEM);
    unsigned interruptions = 0;
    for (;;) {
        ssize_t count = read(fd, sample->bytes + sample->length,
                             HOSTS_BYTES + 1u - sample->length);
        if (count < 0) {
            if (errno == EINTR && ++interruptions < EVENT_ROUNDS) continue;
            return native_error(detail, errno);
        }
        if (count == 0) return PHANTOM_DNS_OK;
        sample->length += (size_t)count;
        if (sample->length > HOSTS_BYTES) return native_error(detail, EFBIG);
    }
}

/* Descriptor-relative resolution follows intermediate/directory symlinks,
 * including /etc -> private/etc. Every traversed existing directory remains
 * watched; ENOENT retains the nearest existing ancestor. No blocking FIFO open.
 * Two independent traversals/full reads below invalidate a crossed preparation
 * without adopting it. Structural/rearm errors remain terminal. */
static uint32_t sample_hosts(struct dns_watch *watch, struct hosts_sample **out,
                             uint32_t *detail) {
    struct hosts_sample *sample = calloc(1, sizeof(*sample));
    if (sample == NULL) return native_error(detail, ENOMEM);
    *out = sample;
    int root = open("/", O_EVTONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) return native_error(detail, errno);
    uint32_t status = sample_fd(watch, sample, root, detail);
    if (status != PHANTOM_DNS_OK) return status;
    struct stat st;
    if (fstat(root, &st) < 0) return native_error(detail, errno);
    status = sample_node(sample, &st, detail);
    if (status != PHANTOM_DNS_OK) return status;
    int parent = root;
    char pending[PATH_MAX];
    memcpy(pending, watch->path, strlen(watch->path) + 1);
    unsigned links = 0;
    for (unsigned step = 0; step < HOSTS_STEPS; ++step) {
        char *start = pending;
        while (*start == '/') ++start;
        if (*start == '\0') return native_error(detail, EINVAL);
        char component[PATH_MAX];
        size_t length = strcspn(start, "/");
        memcpy(component, start, length); component[length] = '\0';
        char *rest = start + length;
        while (*rest == '/') ++rest;
        memmove(pending, rest, strlen(rest) + 1);
        if (fstatat(parent, component, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno == ENOENT) return PHANTOM_DNS_OK;
            return native_error(detail, errno);
        }
        status = sample_node(sample, &st, detail);
        if (status != PHANTOM_DNS_OK) return status;
        if (S_ISLNK(st.st_mode)) {
            if (++links > HOSTS_LINKS) return native_error(detail, ELOOP);
            char target[PATH_MAX];
            ssize_t size = readlinkat(parent, component, target, sizeof(target));
            if (size < 0) return native_error(detail, errno);
            if (size == 0 || (size_t)size >= sizeof(target))
                return native_error(detail, ENAMETOOLONG);
            target[size] = '\0';
            size_t remaining = strlen(pending);
            if ((size_t)size + 1u + remaining >= sizeof(pending))
                return native_error(detail, ENAMETOOLONG);
            memmove(pending + size + 1, pending, remaining + 1);
            memcpy(pending, target, (size_t)size); pending[size] = '/';
            if (target[0] == '/') parent = root;
            continue;
        }
        int final = pending[0] == '\0';
        if ((!final && !S_ISDIR(st.st_mode)) ||
            (final && !S_ISREG(st.st_mode))) return native_error(detail, EINVAL);
        int fd = openat(parent, component, O_NOFOLLOW | O_CLOEXEC |
                        (final ? O_RDONLY | O_NONBLOCK : O_EVTONLY | O_DIRECTORY));
        if (fd < 0) return native_error(detail, errno);
        status = sample_fd(watch, sample, fd, detail);
        if (status != PHANTOM_DNS_OK) return status;
        struct stat opened;
        if (fstat(fd, &opened) < 0) return native_error(detail, errno);
        if (!same_node(&st, &opened)) return native_error(detail, EAGAIN);
        if (final) {
            sample->present = 1;
            return sample_bytes(sample, fd, detail);
        }
        parent = fd;
    }
    return native_error(detail, E2BIG);
}

static int samples_equal(const struct hosts_sample *left,
                         const struct hosts_sample *right) {
    if (left->present != right->present || left->node_count != right->node_count ||
        left->length != right->length) return 0;
    for (size_t i = 0; i < left->node_count; ++i) {
        const struct hosts_node *a = &left->nodes[i], *b = &right->nodes[i];
        if (a->device != b->device || a->inode != b->inode || a->mode != b->mode)
            return 0;
    }
    return left->length == 0 || memcmp(left->bytes, right->bytes, left->length) == 0;
}

static uint32_t drain_vnodes(struct dns_watch *watch, uint32_t *detail) {
    const struct timespec immediate = {0, 0};
    for (unsigned round = 0; round < EVENT_ROUNDS; ++round) {
        struct kevent events[EVENT_BATCH];
        int count = kevent(watch->queue, NULL, 0, events, EVENT_BATCH, &immediate);
        if (count < 0) {
            if (errno == EINTR) continue;
            return native_error(detail, errno);
        }
        if (count == 0) return PHANTOM_DNS_OK;
        for (int i = 0; i < count; ++i) {
            struct kevent *event = &events[i];
            size_t j;
            for (j = 0; j < watch->live_count &&
                 (uintptr_t)watch->live[j] != event->ident; ++j) {}
            if (event->flags & EV_ERROR)
                return native_error(detail, event->data > 0 && event->data <= INT_MAX
                                              ? (int)event->data : EINVAL);
            if (j == watch->live_count || event->filter != EVFILT_VNODE ||
                (event->flags & ~(EV_ADD | EV_CLEAR)) != 0 ||
                event->fflags == 0 || (event->fflags & ~VNODE_FLAGS) != 0)
                return native_error(detail, EINVAL);
            if (event->fflags & NOTE_REVOKE) return native_error(detail, ESTALE);
            watch->pending = 1;
        }
    }
    return native_error(detail, E2BIG);
}

static uint32_t drain_notifications(struct dns_watch *watch, uint32_t *detail) {
    for (unsigned i = 0; i < 2; ++i) {
        for (unsigned round = 0; ; ++round) {
            if (round == EVENT_ROUNDS) return native_error(detail, E2BIG);
            int token;
            ssize_t count = read(watch->fd[i], &token, sizeof(token));
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (count < 0 && errno == EINTR) continue;
            if (count != (ssize_t)sizeof(token))
                return native_error(detail, count < 0 ? errno : EINVAL);
            /* Libnotify historically delivered both byte orders. Framing is
             * checked, but the notification token's payload is not compared. */
            watch->pending = 1;
        }
        int changed = 0;
        uint32_t status = notify_check(watch->token[i], &changed);
        if (status != NOTIFY_STATUS_OK) { *detail = status; return PHANTOM_DNS_NATIVE; }
        if (changed != 0 && changed != 1) return native_error(detail, EINVAL);
        watch->pending |= changed;
    }
    return PHANTOM_DNS_OK;
}

uint32_t phantom_macos_dns_watch_start(const char *hosts_path, void **out,
                                     uint32_t *detail) {
    if (out == NULL || detail == NULL || hosts_path == NULL)
        return PHANTOM_DNS_INVALID;
    *out = NULL; *detail = 0;
    size_t length = strnlen(hosts_path, PATH_MAX);
    if (length == 0 || length == PATH_MAX || hosts_path[0] != '/' ||
        hosts_path[length - 1] == '/')
        return native_error(detail, EINVAL);
    struct dns_watch *watch = calloc(1, sizeof(*watch));
    if (watch == NULL) return native_error(detail, ENOMEM);
    watch->fd[0] = watch->fd[1] = watch->queue = -1;
    watch->token[0] = watch->token[1] = NOTIFY_TOKEN_INVALID;
    /* Transfer before ANY fallible owned setup: caller cancels partial owners. */
    *out = watch;
    watch->path = malloc(length + 1);
    if (watch->path == NULL) return native_error(detail, ENOMEM);
    memcpy(watch->path, hosts_path, length + 1);
    uint32_t status = api_open(&watch->api);
    if (status != PHANTOM_DNS_OK) return status;
    watch->queue = kqueue();
    if (watch->queue < 0) return native_error(detail, errno);
    status = descriptor_setup(watch->queue, 0, detail);
    if (status != PHANTOM_DNS_OK) return status;
    const char *keys[2] = {watch->api.key(), "com.apple.system.hostname"};
    if (keys[0] == NULL || keys[0][0] == '\0') return PHANTOM_DNS_UNAVAILABLE;
    for (unsigned i = 0; i < 2; ++i) {
        *detail = notify_register_file_descriptor(keys[i], &watch->fd[i], 0,
                                                  &watch->token[i]);
        if (*detail != NOTIFY_STATUS_OK) return PHANTOM_DNS_NATIVE;
        status = descriptor_setup(watch->fd[i], 1, detail);
        if (status != PHANTOM_DNS_OK) return status;
    }
    return PHANTOM_DNS_OK;
}

uint32_t phantom_macos_dns_watch_check(void *owner, uint32_t *changed,
                                     uint32_t *detail) {
    if (owner == NULL || changed == NULL || detail == NULL) return PHANTOM_DNS_INVALID;
    struct dns_watch *watch = owner;
    *detail = 0; *changed = 0;
    uint32_t status = drain_vnodes(watch, detail);
    if (status == PHANTOM_DNS_OK) status = drain_notifications(watch, detail);
    char hostname[256];
    memset(hostname, 0xff, sizeof(hostname));
    if (status == PHANTOM_DNS_OK) {
        if (gethostname(hostname, sizeof(hostname)) < 0) status = native_error(detail, errno);
        else if (memchr(hostname, '\0', sizeof(hostname)) == NULL)
            status = native_error(detail, ENAMETOOLONG);
    }
    struct hosts_sample *next = NULL, *verify = NULL;
    if (status == PHANTOM_DNS_OK) status = sample_hosts(watch, &next, detail);
    if (status == PHANTOM_DNS_OK) status = sample_hosts(watch, &verify, detail);
    int crossed = status == PHANTOM_DNS_OK && !samples_equal(next, verify);
    if (status == PHANTOM_DNS_OK) status = drain_vnodes(watch, detail);
    if (status == PHANTOM_DNS_OK) status = drain_notifications(watch, detail);
    if (status == PHANTOM_DNS_OK) {
        char after[256];
        memset(after, 0xff, sizeof(after));
        if (gethostname(after, sizeof(after)) < 0) status = native_error(detail, errno);
        else if (memchr(after, '\0', sizeof(after)) == NULL)
            status = native_error(detail, ENAMETOOLONG);
        else if (strcmp(hostname, after) != 0) crossed = 1;
    }
    /* Startup must never announce readiness without an armed stable baseline. */
    if (status == PHANTOM_DNS_OK && crossed && watch->hosts == NULL)
        status = native_error(detail, EAGAIN);
    if (status == PHANTOM_DNS_OK) {
        if ((watch->hosts != NULL && !samples_equal(watch->hosts, next)) ||
            (watch->hostname_ready && strcmp(hostname, watch->hostname) != 0))
            watch->pending = 1;
        if (crossed) watch->pending = 1;
        else {
            struct hosts_sample *old = watch->hosts;
            watch->hosts = next; next = old;
            memcpy(watch->hostname, hostname, sizeof(hostname));
            watch->hostname_ready = 1;
        }
        *changed = (uint32_t)watch->pending;
        watch->pending = 0;
    }
    /* All replacement watches are armed BEFORE old watches are closed. Even
     * a crossed/error preparation keeps the original sample until owner close. */
    uint32_t cleanup_detail = 0, second_detail = 0;
    uint32_t cleanup = sample_close(watch, next, &cleanup_detail);
    uint32_t second = sample_close(watch, verify, &second_detail);
    if (status == PHANTOM_DNS_OK && cleanup != PHANTOM_DNS_OK)
        status = native_error(detail, (int)cleanup_detail);
    else if (status == PHANTOM_DNS_OK && second != PHANTOM_DNS_OK)
        status = native_error(detail, (int)second_detail);
    return status;
}

uint32_t phantom_macos_dns_watch_wait(void *owner, int control, uint32_t *event,
                                    uint32_t *detail) {
    if (owner == NULL || control < 0 || event == NULL || detail == NULL)
        return PHANTOM_DNS_INVALID;
    struct dns_watch *watch = owner;
    /* XNU kqueue fileops exposes readiness through fo_select. The queue only
     * contains vnode events; poll never consumes its event records. */
    struct pollfd fds[4] = {{control, POLLIN, 0}, {watch->fd[0], POLLIN, 0},
                           {watch->fd[1], POLLIN, 0}, {watch->queue, POLLIN, 0}};
    int ready = poll(fds, 4, 1000);
    if (ready < 0) {
        if (errno == EINTR) { *event = 3; return PHANTOM_DNS_OK; }
        return native_error(detail, errno);
    }
    for (unsigned i = 0; i < 4; ++i)
        if (fds[i].revents & (POLLERR | POLLNVAL)) return native_error(detail, EIO);
    if (fds[0].revents & (POLLIN | POLLHUP)) {
        uint8_t byte;
        ssize_t count = read(control, &byte, 1);
        if (count < 0) return native_error(detail, errno);
        if (count == 1 && byte != 1) return native_error(detail, EINVAL);
        *event = count == 0 ? 0 : 2;
        return PHANTOM_DNS_OK;
    }
    for (unsigned i = 1; i < 4; ++i)
        if (fds[i].revents & POLLHUP) return native_error(detail, EPIPE);
    /* gethostname is sampled on EVERY check, plus this one-second backup.
     * Configd posts its hostname key, but direct kernel sethostname need not.
     * One second is the idle sampling cadence, not a finite delivery bound:
     * synchronous filesystem/native work can delay the next sample. */
    *event = ready == 0 ? 3 : 1;
    return PHANTOM_DNS_OK;
}

uint32_t phantom_macos_dns_watch_close(void *owner, uint32_t *detail) {
    if (owner == NULL || detail == NULL) return PHANTOM_DNS_INVALID;
    struct dns_watch *watch = owner;
    *detail = 0;
    uint32_t status = sample_close(watch, watch->hosts, detail);
    if (watch->queue >= 0) {
        int error = owned_close(watch->queue);
        if (error && status == PHANTOM_DNS_OK) status = native_error(detail, error);
    }
    for (unsigned i = 0; i < 2; ++i) {
        if (watch->token[i] == NOTIFY_TOKEN_INVALID) continue;
        uint32_t error = notify_cancel(watch->token[i]);
        if (error != NOTIFY_STATUS_OK && status == PHANTOM_DNS_OK) {
            *detail = error; status = PHANTOM_DNS_NATIVE;
        }
    }
    /* Failed notify_cancel may retain at most TWO registrations/fds per failed
     * owner. Neither holds a callback/context pointer. Never manually close a
     * library-owned notify fd; all our vnode/kqueue fds were closed above. */
    api_close(&watch->api);
    free(watch->path);
    free(watch);
    return status;
}
