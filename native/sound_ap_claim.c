#include "sound_ap_claim.h"

static uint32_t r16(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8;
}
static uint32_t r32(const uint8_t *p)
{
    return r16(p) | r16(p + 2) << 16;
}

cs_claim_result cs_ap_claim_decode(const uint8_t *reply, size_t bytes,
    const cs_ap_claim_context *context, cs_ap_claim *out)
{
    cs_ap_claim next = {0};
    uint32_t handle;
    uint64_t physical;
    if (reply == NULL || context == NULL || out == NULL || bytes != 40U) {
        return CS_CLAIM_ARGUMENT;
    }
    if (context->endpoint == 0U || context->endpoint == UINT32_MAX ||
        context->token == 0U || context->token > 65535U ||
        context->reply_source != UINT32_C(0x61003c) ||
        r16(reply) != 0x8020U || r16(reply + 6) != context->token ||
        r32(reply + 16) != UINT32_C(0x70817)) { return CS_CLAIM_IDENTITY; }
    if (r16(reply + 2) != 0U || r16(reply + 10) != 0U) { return CS_CLAIM_STATUS; }
    if (r16(reply + 8) != 1U) { return CS_CLAIM_COUNT; }
    handle = r32(reply + 12);
    if (handle > 65535U || (handle & 0x8000U) == 0U ||
        (handle & 1023U) == 1023U || ((handle >> 10) & 31U) == 0U) {
        return CS_CLAIM_HANDLE;
    }
    if (r32(reply + 32) != CS_CELL_BYTES) { return CS_CLAIM_EXTENT; }
    physical = (uint64_t)r32(reply + 24) | (uint64_t)r32(reply + 28) << 32;
    if (physical < CS_PHYS_MIN || physical > CS_PHYS_END ||
        CS_PHYS_END - physical < (uint64_t)CS_CELL_BYTES) { return CS_CLAIM_RANGE; }
    if ((physical & UINT64_C(63)) != 0U) { return CS_CLAIM_ALIGNMENT; }
    next.memory.handle = handle;
    next.memory.endpoint = context->endpoint;
    next.memory.physical = physical;
    next.memory.extent_count = 1U;
    next.memory.capacity = CS_CELL_BYTES;
    next.token = context->token;
    *out = next;
    return CS_CLAIM_OK;
}
