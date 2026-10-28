#ifndef CAMERA_CUBE_INPUT_H
#define CAMERA_CUBE_INPUT_H
#include <stddef.h>
#include <stdint.h>

/* Pure data parser. Values use .cube order: red varies fastest, then green,
 * then blue. Caller supplies temporary storage; never pass the active LUT.
 * On failure temporary storage may change, but *result stays untouched.
 * This does not mount media, publish a LUT or address camera hardware. */
#define CAMERA_CUBE_MAX_SIZE 65u
#define CAMERA_CUBE_MAX_BYTES (32u * 1024u * 1024u)

enum camera_cube_status {
    CAMERA_CUBE_OK = 0, CAMERA_CUBE_ARGUMENT, CAMERA_CUBE_LIMIT,
    CAMERA_CUBE_SYNTAX, CAMERA_CUBE_DIRECTIVE, CAMERA_CUBE_SIZE,
    CAMERA_CUBE_DOMAIN, CAMERA_CUBE_ROWS, CAMERA_CUBE_CAPACITY,
    CAMERA_CUBE_NUMBER
};

struct camera_cube_info {
    uint32_t size, rows;
    double domain_min[3], domain_max[3];
    double output_min[3], output_max[3];
    uint32_t explicit_domain;
};
struct camera_cube_error { uint32_t code, line; };

int camera_cube_parse(const char *text, size_t bytes, float *temporary,
                      size_t capacity_floats, struct camera_cube_info *result,
                      struct camera_cube_error *error);

enum camera_cube_bounds {
    CAMERA_CUBE_REJECT_OUTSIDE = 0, CAMERA_CUBE_CLAMP_OUTSIDE = 1
};

/* Trilinear interpolation in the explicitly declared input domain. No gamma,
 * gamut or camera color-space conversion is inferred. output stays unchanged
 * on failure. Input values must remain immutable throughout the call. */
int camera_cube_sample(const struct camera_cube_info *info, const float *values,
                       size_t count_floats, const double rgb[3],
                       enum camera_cube_bounds bounds, double output[3]);

/* Build a temporary canonical [0,1] grid for the selected 17/33-point input
 * format. Source and temporary buffers must not overlap. On failure result
 * and clamped_nodes stay unchanged; temporary may change. Success here does
 * not publish a LUT or establish native precision/ISP support. */
int camera_cube_resample(const struct camera_cube_info *info, const float *values,
                         size_t count_floats, uint32_t target_size,
                         enum camera_cube_bounds bounds, float *temporary,
                         size_t capacity_floats, struct camera_cube_info *result,
                         uint32_t *clamped_nodes);

#define CAMERA_CUBE_AP_INTEGER_BYTES 48000u
enum camera_cube_quantization {
    CAMERA_CUBE_REJECT_UNREPRESENTABLE = 0, CAMERA_CUBE_SATURATE_Q13 = 1
};
/* Encode the reviewed AP INTEGER path: 17 active nodes, even if input size33.
 * Requires a canonical [0,1] input domain; does not infer a color space. The
 * output is data, not firmware or a camera-installation container. Saturation
 * requires explicit policy; its count covers active output components only. */
int camera_cube_pack_ap_integer(const struct camera_cube_info *info,
                                const float *values, size_t count_floats,
                                enum camera_cube_quantization policy,
                                unsigned char *temporary, size_t capacity_bytes,
                                uint32_t *saturated_components);
#endif
