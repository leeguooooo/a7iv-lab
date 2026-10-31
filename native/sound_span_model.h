#ifndef CS_MODEL_STORE_H
#define CS_MODEL_STORE_H
#include "sound_span.h"
/* Test-only host ownership. Never included by production/core code. */
cs_store *cs_model_store_create(void);
void cs_model_store_destroy(cs_store *store);
#endif
