#ifndef SOUND_CP_BACKING_H
#define SOUND_CP_BACKING_H
#include <stdint.h>

enum { CS_CP_EMPTY, CS_CP_RETAINED, CS_CP_HOLD };
typedef enum { CS_CP_OK, CS_CP_UNAVAILABLE, CS_CP_ARGUMENT, CS_CP_CONTEXT,
               CS_CP_OBSERVATION, CS_CP_GEOMETRY, CS_CP_RETAIN_FAILED,
               CS_CP_IDENTITY, CS_CP_HELD } cs_cp_result;
/* Zero-initialized private CP storage; never reset or release after use.
   attempted_mask includes potentially changed native calls, acquired_mask
   includes only confirmed primary increments. HOLD retains both forever. */
typedef struct {
    uint32_t state, endpoint, handles[3];
    uint32_t physical_low, physical_high, cpu_base, capacity;
    uint32_t acquired_mask, attempted_mask;
} cs_cp_backing;

/* Host/default builds always return UNAVAILABLE without changing storage.
   The research ARM build is callable only from an already-serialized original
   DMM worker. It never acquires/unlocks the native lock itself. This is not a
   general native snapshot provider or proof of live mapping/endpoint cleanup. */
cs_cp_result cs_cp_backing_bind(cs_cp_backing *backing, uint32_t endpoint,
                              const uint32_t handles[3]);
#endif
