#include "sound_snapshot_model.h"
#include "sound_span_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MEMORY = 512, TABLE = 0x1000, NODES = 0x1100 };
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static void put16(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
}
static void put32(unsigned char *p, uint32_t v)
{
    put16(p, v); put16(p + 2, v >> 16);
}
static void put64(unsigned char *p, uint64_t v)
{
    put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32));
}
static void fixture(unsigned char bytes[MEMORY], uint64_t base)
{
    size_t i;
    memset(bytes, 0, MEMORY);
    for (i = 0U; i < 3U; ++i) {
        unsigned char *slot = bytes + i * 64U;
        unsigned char *node = bytes + 256U + i * 32U;
        slot[11] = 1U;
        put16(slot + 12, 1U);
        put16(slot + 14, 1U);
        put32(slot + 16, NODES + (uint32_t)i * 32U);
        put64(node + 8, base + (uint64_t)i * CS_CELL_BYTES - 64U);
        put32(node + 16, 64U);
        put32(node + 20, CS_CELL_BYTES);
    }
}
static const uint32_t handles[3] = {0x8400, 0x8401, 0x8402};

static void rejected(unsigned char *bytes, size_t length, uint32_t table,
    const uint32_t h[3], ss_status expected, size_t reads)
{
    ss_model_snapshot *s = ss_model_snapshot_create(bytes,length,TABLE,table,17U);
    cs_observation out[3];
    unsigned char before[sizeof(out)];
    ss_read_log log;
    ss_status actual;
    CHECK(s != NULL);
    memset(out,0xa5,sizeof(out)); memcpy(before,out,sizeof(out));
    actual = ss_model_observe_three(s,h,out);
    if (actual != expected) {
        fprintf(stderr,"actual=%d expected=%d length=%zu table=%x handle=%x\n",
                (int)actual,(int)expected,length,table,h[0]);
    }
    CHECK(actual == expected);
    CHECK(memcmp(before,out,sizeof(out)) == 0);
    CHECK(ss_model_read_log(s,&log) == SS_OK);
    CHECK(log.count == reads);
    ss_model_snapshot_destroy(s);
}
static void successes(void)
{
    const uint64_t bases[] = {CS_PHYS_MIN,UINT64_C(0x81b810000),CS_PHYS_END-CS_CAPACITY};
    const unsigned orders[6][3] = {{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
    unsigned char bytes[MEMORY];
    size_t b, k, i;
    for (b=0U;b<3U;++b) { for (k=0U;k<6U;++k) {
        uint32_t h[3];
        cs_observation out[3];
        cs_geometry_view view;
        const cs_geometry *g = NULL;
        cs_store *store = cs_model_store_create();
        ss_model_snapshot *s;
        ss_read_log log;
        cs_commit_plan plan;
        cs_real_authority *real = NULL;
        CHECK(store != NULL);
        fixture(bytes,bases[b]);
        for(i=0U;i<3U;++i) { h[i]=handles[orders[k][i]]; }
        s=ss_model_snapshot_create(bytes,sizeof(bytes),TABLE,TABLE,17U);
        CHECK(s != NULL);
        /* Caller mutation cannot alter the published copied model view. */
        memset(bytes,0xff,sizeof(bytes));
        CHECK(ss_model_observe_three(s,h,out) == SS_OK);
        CHECK(ss_model_read_log(s,&log) == SS_OK && log.count == 9U);
        for(i=0U;i<3U;++i) {
            uint32_t index = orders[k][i];
            CHECK(out[i].handle == h[i] && out[i].endpoint == 17U);
            CHECK(out[i].physical == bases[b]+(uint64_t)index*CS_CELL_BYTES);
            CHECK(log.reads[i*3U].kind == SS_SLOT && log.reads[i*3U].bytes == 16U);
            CHECK(log.reads[i*3U].address == TABLE+index*64U);
            CHECK(log.reads[i*3U+1U].kind == SS_POINTER && log.reads[i*3U+1U].bytes == 4U);
            CHECK(log.reads[i*3U+1U].address == TABLE+index*64U+16U);
            CHECK(log.reads[i*3U+2U].kind == SS_EXTENT && log.reads[i*3U+2U].bytes == 16U);
            CHECK(log.reads[i*3U+2U].address == NODES+index*32U+8U);
        }
        CHECK(cs_geometry_build(store,out,&g) == CS_OK);
        CHECK(cs_geometry_inspect(g,&view) == CS_OK && view.physical.value == bases[b]);
        CHECK(cs_commit_plan_make(g,CS_MAX_ENCODED,&plan) == CS_OK);
        CHECK(plan.guard.bytes == 64U && plan.clean.bytes == 123936U);
        CHECK(cs_real_authority_open(&real) == CS_UNAVAILABLE && real == NULL);
        CHECK(ss_model_observe_three(s,h,out) == SS_OK);
        CHECK(ss_model_read_log(s,&log) == SS_OK && log.count == 9U);
        ss_model_snapshot_destroy(s); cs_model_store_destroy(store);
    } }
}
static void invalid_fields(void)
{
    unsigned char bytes[MEMORY];
    uint32_t v;
    uint32_t bad[3] = {0,0x8401,0x8402};
    fixture(bytes,CS_PHYS_MIN);
    /* Every unsupported u16 count rejects with zero pointer/extent reads. */
    for(v=0U;v<=UINT16_MAX;++v) {
        if(v != 1U) { put16(bytes+14,v); rejected(bytes,MEMORY,TABLE,handles,SS_COUNT,1U); }
    }
    put16(bytes+14,1U);
    for(v=0U;v<=UINT16_MAX;++v) {
        if(v<1U || v>3U) { put16(bytes+12,v); rejected(bytes,MEMORY,TABLE,handles,SS_STATE,1U); }
        else {
            ss_model_snapshot *s;
            cs_observation out[3];
            put16(bytes+12,v);
            s=ss_model_snapshot_create(bytes,MEMORY,TABLE,TABLE,17U);
            CHECK(s != NULL && ss_model_observe_three(s,handles,out) == SS_OK);
            ss_model_snapshot_destroy(s);
        }
    }
    put16(bytes+12,1U);
    for(v=0U;v<=UINT8_MAX;++v) {
        if(v!=1U) { bytes[11]=(unsigned char)v; rejected(bytes,MEMORY,TABLE,handles,SS_GENERATION,1U); }
    }
    bytes[11]=1U;
    { const uint32_t values[]={0U,0x400U,0x8000U,0x87ffU,0x18400U,UINT32_MAX};
      size_t i;
      for(i=0U;i<sizeof(values)/sizeof(values[0]);++i) {
          bad[0]=values[i]; rejected(bytes,MEMORY,TABLE,bad,SS_HANDLE,0U);
      }
    }
    put16(bytes+128U+14U,2U);
    rejected(bytes,MEMORY,TABLE,handles,SS_COUNT,7U);
}
static void bounds(void)
{
    unsigned char bytes[MEMORY];
    uint32_t v;
    fixture(bytes,CS_PHYS_MIN);
    rejected(bytes,15U,TABLE,handles,SS_RANGE,0U);
    rejected(bytes,19U,TABLE,handles,SS_RANGE,1U);
    rejected(bytes,MEMORY,UINT32_C(0xfffffffc),handles,SS_RANGE,0U);
    { const uint32_t pointers[]={0U,1U,NODES+1U,TABLE-4U,TABLE+MEMORY-20U,0xfffffffcU};
      size_t i;
      for(i=0U;i<sizeof(pointers)/sizeof(pointers[0]);++i) {
          put32(bytes+16,pointers[i]); rejected(bytes,MEMORY,TABLE,handles,SS_RANGE,2U);
      }
    }
    fixture(bytes,CS_PHYS_MIN);
    for(v=0U;v<16U;++v) {
        put64(bytes+264U,UINT64_MAX-v);
        put32(bytes+272U,v+1U);
        rejected(bytes,MEMORY,TABLE,handles,SS_OVERFLOW,3U);
    }
    CHECK(ss_model_snapshot_create(bytes,MEMORY,UINT32_MAX,TABLE,17U) == NULL);
    CHECK(ss_model_snapshot_create(bytes,MEMORY,TABLE,TABLE,0U) == NULL);
    CHECK(ss_model_snapshot_create(bytes,MEMORY,TABLE,TABLE,UINT32_MAX) == NULL);
    CHECK(ss_model_snapshot_create(bytes,MEMORY,TABLE,TABLE+1U,17U) == NULL);
    CHECK(ss_model_snapshot_create(NULL,MEMORY,TABLE,TABLE,17U) == NULL);
    CHECK(ss_model_snapshot_create(bytes,0U,TABLE,TABLE,17U) == NULL);
    ss_model_snapshot_destroy(NULL);
}
static void geometry_rejections(void)
{
    unsigned char bytes[MEMORY];
    unsigned kind;
    for(kind=0U;kind<4U;++kind) {
        ss_model_snapshot *s;
        cs_observation out[3];
        cs_store *store=cs_model_store_create();
        const cs_geometry *g=NULL;
        cs_result expected;
        uint32_t h[3]={handles[0],handles[1],handles[2]};
        CHECK(store != NULL);
        fixture(bytes,UINT64_C(0x81b810000));
        if(kind==0U) { put32(bytes+276U,51199U); expected=CS_EXTENT; }
        else if(kind==1U) {
            put64(bytes+296U,UINT64_C(0x81b810000)+CS_CELL_BYTES);
            expected=CS_CONTIGUITY;
        }
        else if(kind==2U) { h[2]=h[1]; expected=CS_HANDLE; }
        else { put64(bytes+264U,CS_PHYS_END); expected=CS_RANGE; }
        s=ss_model_snapshot_create(bytes,MEMORY,TABLE,TABLE,17U);
        CHECK(s != NULL && ss_model_observe_three(s,h,out) == SS_OK);
        /* Decoding facts does not establish usable or retained backing. */
        CHECK(cs_geometry_build(store,out,&g) == expected && g == NULL);
        ss_model_snapshot_destroy(s); cs_model_store_destroy(store);
    }
}
static void invalid_arguments(void)
{
    unsigned char bytes[MEMORY];
    cs_observation out[3];
    unsigned char before[sizeof(out)];
    ss_model_snapshot *s;
    ss_read_log log;
    fixture(bytes,CS_PHYS_MIN);
    s=ss_model_snapshot_create(bytes,MEMORY,TABLE,TABLE,17U);
    CHECK(s != NULL && ss_model_observe_three(s,handles,out) == SS_OK);
    memcpy(before,out,sizeof(out));
    CHECK(ss_model_read_log(s,&log) == SS_OK && log.count == 9U);
    CHECK(ss_model_observe_three(s,NULL,out) == SS_ARGUMENT);
    CHECK(memcmp(before,out,sizeof(out)) == 0);
    CHECK(ss_model_read_log(s,&log) == SS_OK && log.count == 0U);
    CHECK(ss_model_observe_three(s,handles,NULL) == SS_ARGUMENT);
    CHECK(ss_model_read_log(s,&log) == SS_OK && log.count == 0U);
    CHECK(ss_model_observe_three(NULL,handles,out) == SS_ARGUMENT);
    CHECK(ss_model_read_log(NULL,&log) == SS_ARGUMENT);
    CHECK(ss_model_read_log(s,NULL) == SS_ARGUMENT);
    ss_model_snapshot_destroy(s);
}
int main(void)
{
    successes(); invalid_fields(); bounds(); geometry_rejections(); invalid_arguments();
    printf("{\"checks\":%u,\"success_geometries\":18,\"all_u16_counts_and_states\":true,\"passed\":true}\n",checks);
    return 0;
}
