#include <stddef.h>
#include <stdint.h>
/* Buffers remain caller owned for the entire call and must not overlap.
 * dispatch output requires 256 KiB; wait requires 256 KiB metadata + 64 KiB data.
 * wait blocks only the single completion pump. Neither function retains pointers.
 */
size_t phantom_go_dispatch(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
size_t phantom_go_wait(uint8_t *, size_t, uint8_t *, size_t);
