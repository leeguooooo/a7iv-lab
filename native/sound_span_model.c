#include "sound_span_model.h"
#include "sound_span_private.h"
#include <stdlib.h>

cs_store *cs_model_store_create(void)
{
    return calloc(1U, sizeof(cs_store));
}

void cs_model_store_destroy(cs_store *store)
{
    free(store);
}
