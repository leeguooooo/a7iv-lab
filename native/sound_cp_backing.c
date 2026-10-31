#include "sound_cp_backing.h"

#if defined(CSND_CP_NATIVE_RESEARCH)
#if !defined(__arm__)
#error CSND_CP_NATIVE_RESEARCH requires the independently tested ARM CP target
#endif
#include "sound_span_private.h"
#include <stddef.h>

#define N32(a) (*(volatile const uint32_t *)(uintptr_t)(a))
#define N16(a) (*(volatile const uint16_t *)(uintptr_t)(a))
#define N8(a) (*(volatile const uint8_t *)(uintptr_t)(a))

static int serialized_context(void)
{
    uint32_t cpsr, cpu, context, lock;
    __asm__ volatile("mrs %0, cpsr" : "=r"(cpsr));
    if ((cpsr & 0x80U) == 0U) { return 0; }
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 5" : "=r"(cpu));
    context = N32(0x1508980U + (cpu & 3U) * 4U);
    if (context == 0U || context > UINT32_MAX - 0x14U || (context & 3U) != 0U ||
        N32(context + 0x10U) != 0x50U || N32(0xd6c854U) < 0x50U) { return 0; }
    lock = N32(0x1501ae4U + (0x50U - 1U) * 4U);
    return lock != 0U && lock <= UINT32_MAX - 12U && (lock & 3U) == 0U &&
           N32(lock) == 1U && N32(lock + 8U) == 1U;
}

static int observe(uint32_t handle, uint32_t endpoint, cs_observation *out,
                   uint32_t *primary)
{
    uint32_t index = handle & 1023U;
    uint32_t generation = (handle >> 10) & 31U;
    uint32_t table, slot, node, state, offset;
    uint64_t physical;
    if (handle > 65535U || (handle & 0x8000U) == 0U ||
        index == 1023U || generation == 0U) { return 0; }
    table = N32(0x1472abcU);
    if (table == 0U || (table & 3U) != 0U ||
        table > UINT32_MAX - index * 64U - 20U) { return 0; }
    slot = table + index * 64U;
    state = N16(slot + 12U);
    *primary = N8(slot + 8U);
    if (N8(slot + 11U) != generation || N32(slot) != 0x70817U ||
        state < 1U || state > 3U || *primary == 0U ||
        N16(slot + 14U) != 1U) { return 0; }
    /* This count check precedes even the first pointer load. */
    node = N32(slot + 16U);
    if (node == 0U || (node & 3U) != 0U || node > UINT32_MAX - 24U) { return 0; }
    physical = (uint64_t)N32(node + 8U) | (uint64_t)N32(node + 12U) << 32;
    offset = N32(node + 16U);
    if (UINT64_MAX - physical < offset) { return 0; }
    out->handle = handle;
    out->endpoint = endpoint;
    out->physical = physical + offset;
    out->extent_count = 1U;
    out->capacity = N32(node + 20U);
    return 1;
}

static uint32_t r16(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8;
}
static uint32_t r32(const uint8_t *p)
{
    return r16(p) | r16(p + 2) << 16;
}
static void w16(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
}
static void w32(uint8_t *p, uint32_t value)
{
    w16(p,value); w16(p + 2,value >> 16);
}

static int retain_primary(uint32_t handle)
{
    uint8_t request[52] = {0}, reply[40] = {0};
    uint32_t result;
    /* Original cmd21 flags0 adds primary only: no variable extent output.
       CP service source records this reference separately in native history. */
    w32(request + 4,0x61003cU);
    w16(request + 12,0x21U);
    w32(request + 16,0x70817U);
    w32(request + 20,handle);
    w16(request + 32,1U);
    result = ((uint32_t (*)(void *,void *,void *))(uintptr_t)0xafc841U)(
        request,reply,reply + 24);
    return result == 2U && r16(reply) == 0x8021U &&
           r16(reply + 2) == 0U && r16(reply + 6) == 1U &&
           r16(reply + 10) == 0U && r32(reply + 12) == handle;
}

cs_cp_result cs_cp_backing_bind(cs_cp_backing *b, uint32_t endpoint,
                              const uint32_t handles[3])
{
    cs_observation observations[3];
    uint32_t primary[3];
    cs_store store = {0};
    const cs_geometry *geometry = NULL;
    cs_geometry_view view;
    size_t i;
    if (b == NULL || handles == NULL || endpoint == 0U || endpoint == UINT32_MAX) {
        return CS_CP_ARGUMENT;
    }
    if (b->state == CS_CP_HOLD) { return CS_CP_HELD; }
    if (b->state > CS_CP_HOLD) { return CS_CP_ARGUMENT; }
    if (b->state == CS_CP_RETAINED) {
        if (b->endpoint != endpoint) { return CS_CP_IDENTITY; }
        for (i = 0U; i < 3U; ++i) {
            if (b->handles[i] != handles[i]) { return CS_CP_IDENTITY; }
        }
    }
    if (!serialized_context()) { return CS_CP_CONTEXT; }
    for (i = 0U; i < 3U; ++i) {
        if (!observe(handles[i],endpoint,&observations[i],&primary[i])) {
            if (b->state == CS_CP_RETAINED) { b->state = CS_CP_HOLD; }
            return CS_CP_OBSERVATION;
        }
        if (b->state == CS_CP_EMPTY && primary[i] == 255U) {
            return CS_CP_RETAIN_FAILED;
        }
    }
    if (cs_geometry_build(&store,observations,&geometry) != CS_OK ||
        cs_geometry_inspect(geometry,&view) != CS_OK) {
        if (b->state == CS_CP_RETAINED) { b->state = CS_CP_HOLD; }
        return CS_CP_GEOMETRY;
    }
    if (b->state == CS_CP_RETAINED) {
        if (b->physical_low != (uint32_t)view.physical.value ||
            b->physical_high != (uint32_t)(view.physical.value >> 32) ||
            b->cpu_base != view.cpu.value || b->capacity != view.capacity ||
            b->acquired_mask != 7U || b->attempted_mask != 7U) {
            b->state = CS_CP_HOLD; return CS_CP_IDENTITY;
        }
        return CS_CP_OK;
    }
    if (b->acquired_mask != 0U || b->attempted_mask != 0U) {
        b->state = CS_CP_HOLD; return CS_CP_HELD;
    }
    b->endpoint = endpoint;
    for (i = 0U; i < 3U; ++i) { b->handles[i] = handles[i]; }
    b->physical_low = (uint32_t)view.physical.value;
    b->physical_high = (uint32_t)(view.physical.value >> 32);
    b->cpu_base = view.cpu.value; b->capacity = view.capacity;
    /* Before any native side effect, enter non-retryable retention state. */
    b->state = CS_CP_HOLD;
    for (i = 0U; i < 3U; ++i) {
        b->attempted_mask |= 1U << i;
        if (!retain_primary(handles[i])) { return CS_CP_RETAIN_FAILED; }
        if (!serialized_context()) { return CS_CP_CONTEXT; }
        {
            cs_observation after;
            uint32_t refs;
            if (!observe(handles[i],endpoint,&after,&refs) ||
                refs != primary[i] + 1U || after.physical != observations[i].physical ||
                after.capacity != observations[i].capacity) { return CS_CP_OBSERVATION; }
        }
        b->acquired_mask |= 1U << i;
    }
    b->state = CS_CP_RETAINED;
    return CS_CP_OK;
}
#else
cs_cp_result cs_cp_backing_bind(cs_cp_backing *b, uint32_t endpoint,
                              const uint32_t handles[3])
{
    (void)b; (void)endpoint; (void)handles;
    return CS_CP_UNAVAILABLE;
}
#endif
