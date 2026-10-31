#ifndef CS_SPAN_CONTRACT_H
#define CS_SPAN_CONTRACT_H
#include <stdint.h>

enum { CS_CELL_COUNT = 3, CS_CELL_BYTES = 51200, CS_CAPACITY = 153600,
       CS_MAX_ENCODED = 123872, CS_GUARD = 64, CS_MAX_COPY = 960 };
#define CS_PHYS_MIN UINT64_C(0x800000000)
#define CS_PHYS_END UINT64_C(0x880000000)

typedef enum {
    CS_OK = 0, CS_UNAVAILABLE = 1, CS_ARGUMENT = 2, CS_STORE_USED = 3,
    CS_ENDPOINT = 4, CS_HANDLE = 5, CS_EXTENT = 6, CS_RANGE = 7,
    CS_ALIGNMENT = 8, CS_CONTIGUITY = 9, CS_LENGTH = 10
} cs_result;

/* Numeric observations only; source/session/wire validation belongs to future
   adapters. Neither observations nor geometry prove retention or mapping. */
typedef struct {
    uint32_t handle;
    uint32_t endpoint;
    uint64_t physical;
    uint32_t extent_count;
    uint32_t capacity;
} cs_observation;
typedef struct { uint64_t value; } cs_physical;
typedef struct { uint32_t value; } cs_cpu_numeric;
typedef struct { cs_cpu_numeric base; uint32_t bytes; } cs_numeric_window;
typedef struct {
    cs_physical physical;
    cs_cpu_numeric cpu;
    uint32_t capacity;
    cs_observation ordered[CS_CELL_COUNT];
} cs_geometry_view;
typedef struct {
    cs_physical physical;
    cs_cpu_numeric cpu;
    uint32_t encoded_bytes;
    cs_numeric_window guard;
    cs_numeric_window clean;
} cs_commit_plan;

typedef struct cs_store cs_store;
typedef struct cs_geometry cs_geometry;
typedef struct cs_real_authority cs_real_authority;

/* Store allocation/lifecycle is deliberately absent from this real header.
   A store builds once. *out=NULL on all errors if out is nonnull; failed build
   leaves store unchanged, including existing successful immutable geometry. */
cs_result cs_geometry_build(cs_store *store,
                            const cs_observation observations[CS_CELL_COUNT],
                            const cs_geometry **out);
/* All numeric result objects remain byte-for-byte unchanged on error. */
cs_result cs_geometry_inspect(const cs_geometry *, cs_geometry_view *out);
cs_result cs_copy_plan(const cs_geometry *, uint32_t offset, uint32_t bytes,
                       cs_numeric_window *out);
cs_result cs_commit_plan_make(const cs_geometry *, uint32_t encoded_bytes,
                              cs_commit_plan *out);
/* Always unavailable, even in a model process. Clears *out if nonnull.
   No constructor flag, callbacks, model selector or native operation exists. */
cs_result cs_real_authority_open(cs_real_authority **out);
#endif
