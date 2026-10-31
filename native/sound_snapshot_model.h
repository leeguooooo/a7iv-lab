#ifndef SOUND_SNAPSHOT_MODEL_H
#define SOUND_SNAPSHOT_MODEL_H
#include <stddef.h>
#include <stdint.h>
#include "sound_span.h"

/* Host-only copied synthetic memory. No native pointers or lease authority. */
typedef struct ss_model_snapshot ss_model_snapshot;
typedef enum { SS_OK, SS_ARGUMENT, SS_MEMORY, SS_HANDLE, SS_GENERATION,
               SS_STATE, SS_COUNT, SS_RANGE, SS_OVERFLOW } ss_status;
typedef enum { SS_SLOT, SS_POINTER, SS_EXTENT } ss_read_kind;
typedef struct { uint32_t address; uint32_t bytes; ss_read_kind kind; } ss_read;
typedef struct { size_t count; ss_read reads[9]; } ss_read_log;

/* Copies bytes before publication. Caller must exclude mutation during create.
   All three queries use the same copy; there is no refresh or native backend.
   Endpoint is a label, not evidence of retained CLAIM ownership.
   Concurrent query/destroy is outside this host-only interface's contract. */
ss_model_snapshot *ss_model_snapshot_create(const unsigned char *bytes,
    size_t length, uint32_t memory_base, uint32_t slot_table, uint32_t endpoint);
void ss_model_snapshot_destroy(ss_model_snapshot *snapshot);
/* No result writes on failure. Log records successful bounded reads only. */
ss_status ss_model_observe_three(ss_model_snapshot *snapshot,
    const uint32_t handles[CS_CELL_COUNT], cs_observation out[CS_CELL_COUNT]);
ss_status ss_model_read_log(const ss_model_snapshot *snapshot, ss_read_log *out);
#endif
