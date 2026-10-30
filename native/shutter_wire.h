#ifndef CAMERA_SHUTTER_WIRE_H
#define CAMERA_SHUTTER_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define SHUTTER_WIRE_MAGIC_SHT2 UINT32_C(0x32544853)

/* AP-side private SHT2 byte boundary. No transport, lease, or playback state. */
enum shutter_wire_operation {
    SHUTTER_WIRE_BIND = 1,
    SHUTTER_WIRE_PREPARE = 2,
    SHUTTER_WIRE_COMMIT = 3,
    SHUTTER_WIRE_POLICY = 4,
    SHUTTER_WIRE_QUERY = 5,
    SHUTTER_WIRE_COPY = 6
};

enum shutter_wire_error {
    SHUTTER_WIRE_OK = 0,
    SHUTTER_WIRE_NULL,
    SHUTTER_WIRE_CAPACITY,
    SHUTTER_WIRE_LENGTH,
    SHUTTER_WIRE_HEADER,
    SHUTTER_WIRE_RESERVED,
    SHUTTER_WIRE_SESSION,
    SHUTTER_WIRE_CORRELATION,
    SHUTTER_WIRE_OPERATION,
    SHUTTER_WIRE_ARGUMENT,
    SHUTTER_WIRE_PAYLOAD,
    SHUTTER_WIRE_MISMATCH,
    SHUTTER_WIRE_PHASE,
    SHUTTER_WIRE_OVERLAP
};

struct shutter_wire_request {
    enum shutter_wire_operation operation;
    uint32_t session;
    uint16_t correlation;
    union {
        struct { uint32_t handle[3]; } bind;
        struct { uint32_t generation, revision; } prepare;
        struct { uint32_t generation, revision, encoded_length, crc32; } commit;
        struct { uint32_t generation, revision, enable; } policy;
        struct { uint32_t mode; } query;
        struct { uint32_t generation, revision, offset, length; } copy;
    } args;
    const uint8_t *payload; /* COPY only. */
    size_t payload_length;
};

struct shutter_wire_expectation {
    uint32_t session;
    enum shutter_wire_operation operation;
    uint16_t correlation;
};

struct shutter_wire_reply {
    uint32_t session;
    enum shutter_wire_operation operation;
    uint16_t correlation;
    uint32_t phase; /* Raw CP value 0..7; never a playback or eligibility claim. */
    uint32_t fields[5]; /* Raw words at reply offsets 20,24,28,32,36. */
};

/* Session must be 1..0xfffffffe and correlation 1..65534 (producer policy).
 * On error, output bytes and *written are unchanged. Overlap between output
 * bytes and request, COPY payload, or written is rejected before any write.
 * No input is retained by the codec. */
enum shutter_wire_error shutter_wire_encode(
    const struct shutter_wire_request *request,
    uint8_t *output, size_t capacity, size_t *written);

/* Exactly 40 bytes. On error, *reply is unchanged. Input may overlap reply. */
enum shutter_wire_error shutter_wire_decode_reply(
    const uint8_t *input, size_t length,
    const struct shutter_wire_expectation *expectation,
    struct shutter_wire_reply *reply);

#endif
