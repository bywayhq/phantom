/* Private, fixed-width projection. No SDK pointer crosses this interface. */
#ifndef PHANTOM_MACOS_DNS_H
#define PHANTOM_MACOS_DNS_H

#include <stdint.h>

#define PHANTOM_DNS_OK 0u
#define PHANTOM_DNS_UNAVAILABLE 1u
#define PHANTOM_DNS_INVALID 2u
#define PHANTOM_DNS_NATIVE 3u
#define PHANTOM_DNS_ABI 1u
#define PHANTOM_DNS_OPTIONS 1u
#define PHANTOM_DNS_RESOLVERS 2u

struct phantom_dns_address {
    uint32_t family; /* 4 or 6, independent of the platform AF_* values. */
    uint32_t port;   /* host byte order */
    uint32_t scope;
    uint32_t flow;
    uint8_t address[16];
};

struct phantom_dns_settings {
    uint32_t abi;
    uint32_t ineligible;
    uint32_t nameserver_count;
    uint32_t search_count;
    uint32_t ndots;
    uint32_t attempts;
    uint32_t retrans_seconds;
    uint32_t rotate;
    struct phantom_dns_address nameservers[3];
    uint8_t search[6][256];
};

/* detail contains only an errno/notify status, never configuration data. */
uint32_t phantom_macos_dns_read(struct phantom_dns_settings *out, uint32_t *detail);
/* Adopt every non-NULL owner, including descriptor-setup failure. */
uint32_t phantom_macos_dns_watch_start(void **out, uint32_t *detail);
/* event: 0=control EOF (stop), 1=native invalidation, 2=one control byte. */
uint32_t phantom_macos_dns_watch_wait(void *owner, int control, uint32_t *event,
                                    uint32_t *detail);
uint32_t phantom_macos_dns_watch_check(void *owner, uint32_t *changed,
                                     uint32_t *detail);
/* Always releases the C owner; a failed notify_cancel may retain its OS token. */
uint32_t phantom_macos_dns_watch_close(void *owner, uint32_t *detail);

#endif
