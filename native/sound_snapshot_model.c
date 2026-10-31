#include "sound_snapshot_model.h"
#include <stdlib.h>
#include <string.h>

struct ss_model_snapshot {
    unsigned char *bytes;
    size_t length;
    uint32_t memory_base;
    uint32_t slot_table;
    uint32_t endpoint;
    ss_read_log log;
};

static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint32_t u16(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8;
}
static const unsigned char *read_at(ss_model_snapshot *s, uint64_t address,
                                  uint32_t bytes, ss_read_kind kind)
{
    uint64_t offset;
    ss_read entry;
    if (address > UINT32_MAX || address < s->memory_base ||
        (uint64_t)bytes > (UINT64_C(1) << 32) - address) { return NULL; }
    offset = address - s->memory_base;
    if (offset > s->length || bytes > s->length - (size_t)offset ||
        s->log.count >= sizeof(s->log.reads) / sizeof(s->log.reads[0])) {
        return NULL;
    }
    entry.address = (uint32_t)address;
    entry.bytes = bytes;
    entry.kind = kind;
    s->log.reads[s->log.count++] = entry;
    return s->bytes + (size_t)offset;
}

ss_model_snapshot *ss_model_snapshot_create(const unsigned char *bytes,
    size_t length, uint32_t memory_base, uint32_t slot_table, uint32_t endpoint)
{
    ss_model_snapshot *s;
    if (bytes == NULL || length == 0U || endpoint == 0U ||
        endpoint == UINT32_MAX || (slot_table & 3U) != 0U ||
        (uint64_t)length > (UINT64_C(1) << 32) - memory_base) { return NULL; }
    s = calloc(1U, sizeof(*s));
    if (s == NULL) { return NULL; }
    s->bytes = malloc(length);
    if (s->bytes == NULL) { free(s); return NULL; }
    memcpy(s->bytes, bytes, length);
    s->length = length;
    s->memory_base = memory_base;
    s->slot_table = slot_table;
    s->endpoint = endpoint;
    return s;
}
void ss_model_snapshot_destroy(ss_model_snapshot *s)
{
    if (s != NULL) { free(s->bytes); free(s); }
}

static ss_status observe(ss_model_snapshot *s, uint32_t handle, cs_observation *out)
{
    const unsigned char *p;
    uint64_t slot;
    uint64_t physical;
    uint32_t extent;
    uint32_t offset;
    uint32_t state;
    uint32_t index = handle & UINT32_C(0x3ff);
    uint32_t generation = (handle >> 10) & UINT32_C(31);
    if (handle > UINT32_C(0xffff) || (handle & UINT32_C(0x8000)) == 0U ||
        index == UINT32_C(0x3ff) || generation == 0U) { return SS_HANDLE; }
    slot = (uint64_t)s->slot_table + (uint64_t)index * 64U;
    p = read_at(s, slot, 16U, SS_SLOT);
    if (p == NULL) { return SS_RANGE; }
    if (generation != p[11]) { return SS_GENERATION; }
    state = u16(p + 12);
    if (state < 1U || state > 3U) { return SS_STATE; }
    /* Reject before loading even the first extent pointer. */
    if (u16(p + 14) != 1U) { return SS_COUNT; }
    p = read_at(s, slot + 16U, 4U, SS_POINTER);
    if (p == NULL) { return SS_RANGE; }
    extent = u32(p);
    if (extent == 0U || extent < s->memory_base || (extent & 3U) != 0U) {
        return SS_RANGE;
    }
    p = read_at(s, (uint64_t)extent + 8U, 16U, SS_EXTENT);
    if (p == NULL) { return SS_RANGE; }
    physical = (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32;
    offset = u32(p + 8);
    if (UINT64_MAX - physical < offset) { return SS_OVERFLOW; }
    out->handle = handle;
    out->endpoint = s->endpoint;
    out->physical = physical + offset;
    out->extent_count = 1U;
    out->capacity = u32(p + 12);
    return SS_OK;
}

ss_status ss_model_observe_three(ss_model_snapshot *s,
    const uint32_t handles[CS_CELL_COUNT], cs_observation out[CS_CELL_COUNT])
{
    cs_observation next[CS_CELL_COUNT] = {{0}};
    size_t i;
    ss_status status;
    if (s == NULL) { return SS_ARGUMENT; }
    memset(&s->log, 0, sizeof(s->log));
    if (handles == NULL || out == NULL) { return SS_ARGUMENT; }
    for (i = 0U; i < CS_CELL_COUNT; ++i) {
        status = observe(s, handles[i], &next[i]);
        if (status != SS_OK) { return status; }
    }
    memcpy(out, next, sizeof(next));
    return SS_OK;
}
ss_status ss_model_read_log(const ss_model_snapshot *s, ss_read_log *out)
{
    if (s == NULL || out == NULL) { return SS_ARGUMENT; }
    *out = s->log;
    return SS_OK;
}
