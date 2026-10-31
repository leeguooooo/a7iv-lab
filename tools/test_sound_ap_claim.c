#include "sound_ap_claim.h"
#include "sound_span_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1); } } while (0)
static void w16(uint8_t *p,uint32_t v)
{
    p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);
}
static void w32(uint8_t *p,uint32_t v)
{
    w16(p,v);w16(p+2,v>>16);
}
static void physical(uint8_t *p,uint64_t v)
{
    w32(p+24,(uint32_t)v);w32(p+28,(uint32_t)(v>>32));
}
static void fixture(uint8_t p[40],uint32_t token)
{
    memset(p,0,40U);w16(p,0x8020U);w16(p+6,token);w16(p+8,1U);
    w32(p+12,0x8400U);w32(p+16,0x70817U);
    physical(p,UINT64_C(0x81b810000));w32(p+32,51200U);
}
static void reject(const uint8_t *p,size_t bytes,const cs_ap_claim_context *ctx,
                   cs_claim_result expected)
{
    cs_ap_claim out;
    unsigned char saved[sizeof(out)];
    memset(&out,0xa5,sizeof(out));memcpy(saved,&out,sizeof(out));
    CHECK(cs_ap_claim_decode(p,bytes,ctx,&out)==expected);
    CHECK(memcmp(saved,&out,sizeof(out))==0);
}
static void successful(void)
{
    const uint64_t bases[]={CS_PHYS_MIN,UINT64_C(0x81b810000),CS_PHYS_END-CS_CELL_BYTES};
    const uint32_t tokens[]={1U,55U,65535U};
    cs_ap_claim_context context={0x80550037U,1U,0x61003cU};
    size_t b,t;
    for(b=0U;b<3U;++b)for(t=0U;t<3U;++t){
        uint8_t reply[40],before[40];cs_ap_claim out;
        context.token=tokens[t];fixture(reply,tokens[t]);physical(reply,bases[b]);
        memcpy(before,reply,40U);
        CHECK(cs_ap_claim_decode(reply,40U,&context,&out)==CS_CLAIM_OK);
        CHECK(out.memory.physical==bases[b] && out.memory.handle==0x8400U);
        CHECK(out.memory.endpoint==context.endpoint && out.token==tokens[t]);
        CHECK(out.memory.extent_count==1U && out.memory.capacity==51200U);
        CHECK(memcmp(before,reply,40U)==0);
    }
}
static void invalid(void)
{
    cs_ap_claim_context good={0x80550037U,55U,0x61003cU},c;
    uint8_t reply[80];size_t n;uint32_t i;
    fixture(reply,55U);
    for(n=0U;n<=80U;++n)if(n!=40U)reject(reply,n,&good,CS_CLAIM_ARGUMENT);
    reject(NULL,40U,&good,CS_CLAIM_ARGUMENT);
    reject(reply,40U,NULL,CS_CLAIM_ARGUMENT);
    CHECK(cs_ap_claim_decode(reply,40U,&good,NULL)==CS_CLAIM_ARGUMENT);
    c=good;c.endpoint=0U;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    c.endpoint=UINT32_MAX;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    c=good;c.token=0U;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    c.token=65536U;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    c=good;c.reply_source=0U;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    c.reply_source=0x9061003cU;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    c=good;c.token=54U;reject(reply,40U,&c,CS_CLAIM_IDENTITY);
    w16(reply,0x802aU);reject(reply,40U,&good,CS_CLAIM_IDENTITY);fixture(reply,55U);
    w32(reply+16,0x70818U);reject(reply,40U,&good,CS_CLAIM_IDENTITY);fixture(reply,55U);
    for(i=1U;i<=65535U;i*=255U){
        w16(reply+2,i);reject(reply,40U,&good,CS_CLAIM_STATUS);w16(reply+2,0U);
        w16(reply+10,i);reject(reply,40U,&good,CS_CLAIM_STATUS);w16(reply+10,0U);
    }
    { const uint32_t counts[]={0U,2U,12U,65535U};
      for(n=0U;n<4U;++n){w16(reply+8,counts[n]);reject(reply,40U,&good,CS_CLAIM_COUNT);}
      w16(reply+8,1U); }
    { const uint32_t handles[]={0U,0x8000U,0x8001U,0x87ffU,0x18400U,UINT32_MAX};
      for(n=0U;n<6U;++n){w32(reply+12,handles[n]);reject(reply,40U,&good,CS_CLAIM_HANDLE);}
      w32(reply+12,0x8400U); }
    w32(reply+32,51199U);reject(reply,40U,&good,CS_CLAIM_EXTENT);
    w32(reply+32,51201U);reject(reply,40U,&good,CS_CLAIM_EXTENT);w32(reply+32,51200U);
    { const uint64_t bases[]={CS_PHYS_MIN-64U,CS_PHYS_END,CS_PHYS_END-CS_CELL_BYTES+64U,
                             UINT64_MAX,UINT64_MAX-63U};
      for(n=0U;n<5U;++n){physical(reply,bases[n]);reject(reply,40U,&good,CS_CLAIM_RANGE);} }
    physical(reply,CS_PHYS_MIN+1U);reject(reply,40U,&good,CS_CLAIM_ALIGNMENT);
}
static void combine(void)
{
    cs_observation group[3];cs_ap_claim out;
    cs_ap_claim_context c={0x80550037U,55U,0x61003cU};
    cs_store *store=cs_model_store_create();const cs_geometry *g=NULL;
    cs_geometry_view view;
    uint8_t reply[40];size_t i;
    CHECK(store!=NULL);
    for(i=0U;i<3U;++i){
        fixture(reply,55U);w32(reply+12,0x8400U+(uint32_t)i);
        physical(reply,UINT64_C(0x81b810000)+(uint64_t)(2U-i)*CS_CELL_BYTES);
        CHECK(cs_ap_claim_decode(reply,40U,&c,&out)==CS_CLAIM_OK);
        group[i]=out.memory;
    }
    CHECK(cs_geometry_build(store,group,&g)==CS_OK);
    CHECK(cs_geometry_inspect(g,&view)==CS_OK);
    CHECK(view.physical.value==UINT64_C(0x81b810000));
    CHECK(view.ordered[0].handle==0x8402U && view.capacity==CS_CAPACITY);
    cs_model_store_destroy(store);
    store=cs_model_store_create();CHECK(store!=NULL);
    group[1].endpoint++;
    CHECK(cs_geometry_build(store,group,&g)==CS_ENDPOINT && g==NULL);
    cs_model_store_destroy(store);
}
int main(void)
{
    successful();invalid();combine();
    printf("{\"checks\":%u,\"passed\":true,\"numeric_only\":true}\n",checks);
    return 0;
}
