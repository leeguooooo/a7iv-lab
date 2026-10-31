#include "sound_span_private.h"
#include <stddef.h>

_Static_assert(CS_CELL_COUNT * CS_CELL_BYTES == CS_CAPACITY, "capacity");
_Static_assert(CS_MAX_ENCODED + CS_GUARD <= CS_CAPACITY, "guard capacity");

static int canonical_handle(uint32_t handle)
{
    return handle <= UINT32_C(0xffff) &&
           (handle & UINT32_C(0x8000)) != 0U &&
           (handle & UINT32_C(0x03ff)) != UINT32_C(0x03ff) &&
           ((handle >> 10) & UINT32_C(0x1f)) != 0U;
}

cs_result cs_geometry_build(cs_store *store,
                            const cs_observation observations[CS_CELL_COUNT],
                            const cs_geometry **out)
{
    cs_geometry_view next = {0};
    uint32_t endpoint;
    size_t i;
    size_t j;
    if (out == NULL) { return CS_ARGUMENT; }
    *out = NULL;
    if (store == NULL || observations == NULL) { return CS_ARGUMENT; }
    if (store->built != 0U) { return CS_STORE_USED; }
    endpoint = observations[0].endpoint;
    if (endpoint == 0U || endpoint == UINT32_MAX) { return CS_ENDPOINT; }
    for (i = 0U; i < CS_CELL_COUNT; ++i) {
        const cs_observation cell = observations[i];
        if (cell.endpoint != endpoint) { return CS_ENDPOINT; }
        if (!canonical_handle(cell.handle)) { return CS_HANDLE; }
        for (j = 0U; j < i; ++j) {
            if (observations[j].handle == cell.handle) { return CS_HANDLE; }
        }
        if (cell.extent_count != 1U || cell.capacity != CS_CELL_BYTES) {
            return CS_EXTENT;
        }
        /* Subtraction first: no unchecked base+capacity, even for UINT64_MAX. */
        if (cell.physical < CS_PHYS_MIN || cell.physical > CS_PHYS_END ||
            CS_PHYS_END - cell.physical < (uint64_t)CS_CELL_BYTES) {
            return CS_RANGE;
        }
        if ((cell.physical & UINT64_C(63)) != 0U) { return CS_ALIGNMENT; }
        next.ordered[i] = cell;
    }
    /* Complete-record insertion sort preserves handle/source association. */
    for (i = 1U; i < CS_CELL_COUNT; ++i) {
        const cs_observation cell = next.ordered[i];
        j = i;
        while (j > 0U && next.ordered[j - 1U].physical > cell.physical) {
            next.ordered[j] = next.ordered[j - 1U];
            --j;
        }
        next.ordered[j] = cell;
    }
    next.physical.value = next.ordered[0].physical;
    if (CS_PHYS_END - next.physical.value < (uint64_t)CS_CAPACITY) {
        return CS_RANGE;
    }
    for (i = 1U; i < CS_CELL_COUNT; ++i) {
        /* Per-cell range already bounded; subtraction rejects overlap too. */
        if (next.ordered[i].physical - next.ordered[i - 1U].physical !=
            (uint64_t)CS_CELL_BYTES) {
            return CS_CONTIGUITY;
        }
    }
    next.cpu.value = (uint32_t)(next.physical.value - CS_PHYS_MIN);
    next.capacity = CS_CAPACITY;
    store->geometry.view = next;
    store->built = 1U;
    *out = &store->geometry;
    return CS_OK;
}

cs_result cs_geometry_inspect(const cs_geometry *geometry, cs_geometry_view *out)
{
    if (geometry == NULL || out == NULL) { return CS_ARGUMENT; }
    *out = geometry->view;
    return CS_OK;
}

cs_result cs_copy_plan(const cs_geometry *geometry, uint32_t offset,
                       uint32_t bytes, cs_numeric_window *out)
{
    cs_numeric_window next;
    if (geometry == NULL || out == NULL) { return CS_ARGUMENT; }
    if (bytes == 0U || bytes > CS_MAX_COPY || offset > CS_MAX_ENCODED ||
        bytes > (uint32_t)CS_MAX_ENCODED - offset) { return CS_LENGTH; }
    next.base.value = geometry->view.cpu.value + offset;
    next.bytes = bytes;
    *out = next;
    return CS_OK;
}

cs_result cs_commit_plan_make(const cs_geometry *geometry,
                              uint32_t encoded_bytes, cs_commit_plan *out)
{
    cs_commit_plan next = {0};
    if (geometry == NULL || out == NULL) { return CS_ARGUMENT; }
    if (encoded_bytes == 0U || encoded_bytes > CS_MAX_ENCODED ||
        (encoded_bytes & UINT32_C(31)) != 0U) { return CS_LENGTH; }
    next.physical = geometry->view.physical;
    next.cpu = geometry->view.cpu;
    next.encoded_bytes = encoded_bytes;
    next.guard.base.value = next.cpu.value + encoded_bytes;
    next.guard.bytes = CS_GUARD;
    next.clean.base = next.cpu;
    next.clean.bytes = encoded_bytes + CS_GUARD;
    *out = next;
    return CS_OK;
}
