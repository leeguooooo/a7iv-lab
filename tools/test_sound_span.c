#include "sound_span.h"
#include "sound_span_model.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(expr) do { assert(expr); ++checks; } while (0)

static void observations(cs_observation cells[CS_CELL_COUNT], uint64_t base)
{
    size_t i;
    for (i = 0U; i < CS_CELL_COUNT; ++i) {
        cells[i].handle = UINT32_C(0x8401) + (uint32_t)i;
        cells[i].endpoint = UINT32_C(0x12345678);
        cells[i].physical = base + (uint64_t)i * CS_CELL_BYTES;
        cells[i].extent_count = 1U;
        cells[i].capacity = CS_CELL_BYTES;
    }
}

static void unavailable(void)
{
    /* Host sentinel only; never dereferenced and never a native address. */
    cs_real_authority *authority = (cs_real_authority *)(void *)&checks;
    CHECK(cs_real_authority_open(&authority) == CS_UNAVAILABLE);
    CHECK(authority == NULL);
    CHECK(cs_real_authority_open(NULL) == CS_UNAVAILABLE);
}

static void success_case(uint64_t base, const unsigned permutation[3])
{
    cs_observation canonical[3];
    cs_observation cells[3];
    cs_observation original[3];
    cs_store *store = cs_model_store_create();
    const cs_geometry *geometry = NULL;
    const cs_geometry *second;
    cs_geometry_view view;
    cs_geometry_view after;
    cs_commit_plan plan;
    cs_numeric_window copy;
    const uint32_t lengths[] = {32U, 4960U, CS_MAX_ENCODED};
    size_t i;
    CHECK(store != NULL);
    observations(canonical, base);
    for (i = 0U; i < 3U; ++i) { cells[i] = canonical[permutation[i]]; }
    memcpy(original, cells, sizeof(cells));
    CHECK(cs_geometry_build(store, cells, &geometry) == CS_OK);
    CHECK(geometry != NULL);
    CHECK(memcmp(cells, original, sizeof(cells)) == 0);
    CHECK(cs_geometry_inspect(geometry, &view) == CS_OK);
    CHECK(view.physical.value == base);
    CHECK((uint64_t)view.cpu.value == base - CS_PHYS_MIN);
    CHECK(view.capacity == CS_CAPACITY);
    CHECK(memcmp(view.ordered, canonical, sizeof(canonical)) == 0);
    for (i = 0U; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        const uint32_t n = lengths[i];
        CHECK(cs_commit_plan_make(geometry, n, &plan) == CS_OK);
        CHECK(plan.physical.value == base);
        CHECK(plan.cpu.value == view.cpu.value);
        CHECK(plan.encoded_bytes == n);
        CHECK(plan.guard.base.value == view.cpu.value + n);
        CHECK(plan.guard.bytes == 64U);
        CHECK(plan.clean.base.value == view.cpu.value);
        CHECK(plan.clean.bytes == n + 64U);
    }
    CHECK(CS_CAPACITY - plan.clean.bytes == 29664U);
    CHECK(cs_copy_plan(geometry, 51168U, 96U, &copy) == CS_OK);
    CHECK(copy.base.value == view.cpu.value + 51168U && copy.bytes == 96U);
    CHECK(cs_copy_plan(geometry, 102336U, 96U, &copy) == CS_OK);
    CHECK(copy.base.value == view.cpu.value + 102336U && copy.bytes == 96U);
    CHECK(cs_copy_plan(geometry, 0U, 960U, &copy) == CS_OK);
    CHECK(cs_copy_plan(geometry, CS_MAX_ENCODED - 1U, 1U, &copy) == CS_OK);
    second = geometry;
    cells[0].physical = UINT64_MAX;
    CHECK(cs_geometry_build(store, cells, &second) == CS_STORE_USED);
    CHECK(second == NULL);
    CHECK(cs_geometry_inspect(geometry, &after) == CS_OK);
    CHECK(memcmp(&view, &after, sizeof(view)) == 0);
    /* Even exact repeat is forbidden: publication retry policy is not here. */
    second = geometry;
    CHECK(cs_geometry_build(store, original, &second) == CS_STORE_USED);
    CHECK(second == NULL);
    unavailable();
    cs_model_store_destroy(store);
}

static void rejection(cs_observation cells[3], cs_result expected)
{
    cs_observation original[3];
    cs_store *store = cs_model_store_create();
    const cs_geometry *geometry = NULL;
    CHECK(store != NULL);
    memcpy(original, cells, sizeof(original));
    CHECK(cs_geometry_build(store, cells, &geometry) == expected);
    CHECK(geometry == NULL);
    CHECK(memcmp(cells, original, sizeof(original)) == 0);
    /* A rejected build did not consume or damage the empty store. */
    observations(cells, UINT64_C(0x81b810000));
    CHECK(cs_geometry_build(store, cells, &geometry) == CS_OK);
    CHECK(geometry != NULL);
    cs_model_store_destroy(store);
}

static void negative_geometry(void)
{
    cs_observation c[3];
    const uint32_t handles[] = {0U, UINT32_MAX, 0x18401U, 0x0401U,
                                0x8001U, 0x87ffU};
    const uint32_t endpoints[] = {0U, UINT32_MAX};
    const uint32_t counts[] = {0U, 2U, 12U, UINT32_MAX};
    const uint32_t capacities[] = {0U, 51199U, 51201U, UINT32_MAX};
    const uint64_t bases[] = {CS_PHYS_MIN - 64U, CS_PHYS_END,
                              UINT64_MAX, UINT64_C(0x900000000)};
    size_t i;
    for (i = 0U; i < sizeof(handles)/sizeof(handles[0]); ++i) {
        observations(c, CS_PHYS_MIN); c[1].handle = handles[i];
        rejection(c, CS_HANDLE);
    }
    for (i = 0U; i < sizeof(endpoints)/sizeof(endpoints[0]); ++i) {
        observations(c, CS_PHYS_MIN); c[0].endpoint = endpoints[i];
        rejection(c, CS_ENDPOINT);
    }
    observations(c, CS_PHYS_MIN); c[1].endpoint++;
    rejection(c, CS_ENDPOINT);
    observations(c, CS_PHYS_MIN); c[1].handle = c[2].handle;
    rejection(c, CS_HANDLE);
    for (i = 0U; i < sizeof(counts)/sizeof(counts[0]); ++i) {
        observations(c, CS_PHYS_MIN); c[2].extent_count = counts[i];
        rejection(c, CS_EXTENT);
    }
    for (i = 0U; i < sizeof(capacities)/sizeof(capacities[0]); ++i) {
        observations(c, CS_PHYS_MIN); c[2].capacity = capacities[i];
        rejection(c, CS_EXTENT);
    }
    for (i = 0U; i < sizeof(bases)/sizeof(bases[0]); ++i) {
        observations(c, CS_PHYS_MIN); c[0].physical = bases[i];
        rejection(c, CS_RANGE);
    }
    observations(c, CS_PHYS_END - CS_CAPACITY + 64U);
    rejection(c, CS_RANGE);
    observations(c, CS_PHYS_MIN + 1U);
    rejection(c, CS_ALIGNMENT);
    observations(c, CS_PHYS_MIN); c[1].physical += 64U;
    rejection(c, CS_CONTIGUITY);
    observations(c, CS_PHYS_MIN); c[1].physical -= 64U;
    rejection(c, CS_CONTIGUITY);
    observations(c, CS_PHYS_MIN); c[1].physical = c[0].physical;
    rejection(c, CS_CONTIGUITY);
}

static void negative_plans(void)
{
    const uint32_t bad_lengths[] = {0U, 1U, 31U, 123873U, 123904U, UINT32_MAX};
    const uint32_t bad_copies[][2] = {{0U,0U}, {0U,961U}, {123872U,1U},
        {123871U,2U}, {UINT32_MAX,1U}, {1U,UINT32_MAX}};
    cs_observation c[3];
    cs_store *store = cs_model_store_create();
    const cs_geometry *geometry = NULL;
    cs_commit_plan plan;
    cs_commit_plan original;
    cs_numeric_window copy;
    cs_numeric_window copy_original;
    size_t i;
    CHECK(store != NULL);
    observations(c, CS_PHYS_END - CS_CAPACITY);
    CHECK(cs_geometry_build(store, c, &geometry) == CS_OK);
    memset(&original, 0xa5, sizeof(original));
    memset(&copy_original, 0x5a, sizeof(copy_original));
    for (i = 0U; i < sizeof(bad_lengths)/sizeof(bad_lengths[0]); ++i) {
        memcpy(&plan, &original, sizeof(plan));
        CHECK(cs_commit_plan_make(geometry, bad_lengths[i], &plan) == CS_LENGTH);
        CHECK(memcmp(&plan, &original, sizeof(plan)) == 0);
    }
    for (i = 0U; i < sizeof(bad_copies)/sizeof(bad_copies[0]); ++i) {
        memcpy(&copy, &copy_original, sizeof(copy));
        CHECK(cs_copy_plan(geometry, bad_copies[i][0], bad_copies[i][1],
                           &copy) == CS_LENGTH);
        CHECK(memcmp(&copy, &copy_original, sizeof(copy)) == 0);
    }
    memcpy(&plan, &original, sizeof(plan));
    CHECK(cs_commit_plan_make(NULL,32U,&plan) == CS_ARGUMENT);
    CHECK(memcmp(&plan,&original,sizeof(plan)) == 0);
    CHECK(cs_commit_plan_make(geometry,32U,NULL) == CS_ARGUMENT);
    memcpy(&copy,&copy_original,sizeof(copy));
    CHECK(cs_copy_plan(NULL,0U,32U,&copy) == CS_ARGUMENT);
    CHECK(memcmp(&copy,&copy_original,sizeof(copy)) == 0);
    CHECK(cs_copy_plan(geometry,0U,32U,NULL) == CS_ARGUMENT);
    CHECK(cs_geometry_inspect(geometry,NULL) == CS_ARGUMENT);
    cs_model_store_destroy(store);
}

static void arguments(void)
{
    cs_store *store = cs_model_store_create();
    cs_observation c[3];
    const cs_geometry *g = NULL;
    cs_geometry_view view;
    cs_geometry_view original;
    CHECK(store != NULL);
    observations(c, CS_PHYS_MIN);
    CHECK(cs_geometry_build(NULL,c,&g) == CS_ARGUMENT && g == NULL);
    CHECK(cs_geometry_build(store,NULL,&g) == CS_ARGUMENT && g == NULL);
    CHECK(cs_geometry_build(store,c,NULL) == CS_ARGUMENT);
    CHECK(cs_geometry_build(store,c,&g) == CS_OK);
    memset(&original,0x5a,sizeof(original));
    memcpy(&view,&original,sizeof(view));
    CHECK(cs_geometry_inspect(NULL,&view) == CS_ARGUMENT);
    CHECK(memcmp(&view,&original,sizeof(view)) == 0);
    cs_model_store_destroy(store);
}

static void handle_boundaries(void)
{
    cs_observation c[3];
    cs_store *store;
    const cs_geometry *g = NULL;
    cs_geometry_view view;
    observations(c,CS_PHYS_MIN);
    c[0].handle = UINT32_C(0x8400); /* generation1, index0 */
    c[1].handle = UINT32_C(0xfffe); /* generation31, index1022 */
    c[2].handle = UINT32_C(0xfc01); /* generation31, index1 */
    store = cs_model_store_create();
    CHECK(store != NULL);
    CHECK(cs_geometry_build(store,c,&g) == CS_OK);
    CHECK(cs_geometry_inspect(g,&view) == CS_OK);
    CHECK(view.ordered[0].handle == UINT32_C(0x8400));
    CHECK(view.ordered[1].handle == UINT32_C(0xfffe));
    CHECK(view.ordered[2].handle == UINT32_C(0xfc01));
    cs_model_store_destroy(store);
}

int main(void)
{
    const unsigned permutations[6][3] = {
        {0U,1U,2U}, {0U,2U,1U}, {1U,0U,2U},
        {1U,2U,0U}, {2U,0U,1U}, {2U,1U,0U}
    };
    const uint64_t bases[] = {CS_PHYS_MIN, UINT64_C(0x81b800000),
        UINT64_C(0x81b810000), UINT64_C(0x823456780), CS_PHYS_END-CS_CAPACITY};
    size_t i;
    size_t j;
    unavailable();
    for (i = 0U; i < sizeof(bases)/sizeof(bases[0]); ++i) {
        for (j = 0U; j < 6U; ++j) { success_case(bases[i], permutations[j]); }
    }
    negative_geometry();
    negative_plans();
    arguments();
    handle_boundaries();
    unavailable();
    printf("{\"checks\":%u,\"success_geometries\":30,\"passed\":true}\n",checks);
    return 0;
}
