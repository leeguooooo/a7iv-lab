#ifndef SOUND_AP_CLAIM_H
#define SOUND_AP_CLAIM_H
#include <stddef.h>
#include <stdint.h>
#include "sound_span.h"

typedef struct { uint32_t endpoint, token, reply_source; } cs_ap_claim_context;
typedef struct { cs_observation memory; uint32_t token; } cs_ap_claim;
typedef enum { CS_CLAIM_OK, CS_CLAIM_ARGUMENT, CS_CLAIM_IDENTITY,
               CS_CLAIM_STATUS, CS_CLAIM_COUNT, CS_CLAIM_HANDLE,
               CS_CLAIM_EXTENT, CS_CLAIM_RANGE, CS_CLAIM_ALIGNMENT } cs_claim_result;

/* Decode only an original CP cmd20, pool70817, single51200-byte CLAIM reply.
   Context is caller-provided transport data, not an endpoint/lease capability.
   The caller must retain the real RPC endpoint and its acquired references.
   Failure leaves the entire output unchanged. Arguments must be disjoint.
   DMM token65535 remains valid; SHT2's separate token limit is not applied. */
cs_claim_result cs_ap_claim_decode(const uint8_t *reply, size_t bytes,
    const cs_ap_claim_context *context, cs_ap_claim *out);
#endif
