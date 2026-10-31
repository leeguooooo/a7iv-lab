#ifndef CS_SPAN_PRIVATE_H
#define CS_SPAN_PRIVATE_H
#include "sound_span.h"
/* Fixed value storage. No target owner layout or native BSS placement implied. */
struct cs_geometry { cs_geometry_view view; };
struct cs_store { uint32_t built; struct cs_geometry geometry; };
#endif
