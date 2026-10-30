#include "shutter_wire.h"

#include <stdint.h>

enum { REQUEST_HEADER = 40, REPLY_BYTES = 40, MAX_COPY = 960, MAX_ENCODED = 123872 };

static void put16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *p, uint32_t value) {
    put16(p, (uint16_t)value);
    put16(p + 2, (uint16_t)(value >> 16));
}

static uint16_t get16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get32(const uint8_t *p) {
    return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16);
}

static int valid_session(uint32_t value) {
    return value != 0 && value != UINT32_MAX;
}

static int ranges_overlap_or_wrap(const void *a, size_t a_length, const void *b, size_t b_length) {
    uintptr_t aa = (uintptr_t)a;
    uintptr_t bb = (uintptr_t)b;
    if (a_length == 0 || b_length == 0) return 0;
    if (a_length > UINTPTR_MAX - aa || b_length > UINTPTR_MAX - bb) return 1;
    return aa < bb + b_length && bb < aa + a_length;
}

enum shutter_wire_error shutter_wire_encode(
    const struct shutter_wire_request *request,
    uint8_t *output, size_t capacity, size_t *written) {
    uint32_t words[4] = {0, 0, 0, 0};
    size_t length = REQUEST_HEADER;
    if (!request || !output || !written) return SHUTTER_WIRE_NULL;
    if (!valid_session(request->session)) return SHUTTER_WIRE_SESSION;
    if (request->correlation == 0 || request->correlation == UINT16_MAX)
        return SHUTTER_WIRE_CORRELATION;
    switch (request->operation) {
    case SHUTTER_WIRE_BIND:
        for (size_t i = 0; i < 3; ++i) {
            uint32_t handle = request->args.bind.handle[i];
            if (handle == 0 || handle == UINT32_MAX) return SHUTTER_WIRE_ARGUMENT;
            for (size_t j = 0; j < i; ++j)
                if (handle == request->args.bind.handle[j]) return SHUTTER_WIRE_ARGUMENT;
            words[i] = handle;
        }
        break;
    case SHUTTER_WIRE_PREPARE:
        words[0] = request->args.prepare.generation;
        words[1] = request->args.prepare.revision;
        if (words[0] == 0) return SHUTTER_WIRE_ARGUMENT;
        break;
    case SHUTTER_WIRE_COMMIT:
        words[0] = request->args.commit.generation;
        words[1] = request->args.commit.revision;
        words[2] = request->args.commit.encoded_length;
        words[3] = request->args.commit.crc32;
        if (words[0] == 0 || words[2] == 0 || words[2] > MAX_ENCODED || (words[2] & 31u))
            return SHUTTER_WIRE_ARGUMENT;
        break;
    case SHUTTER_WIRE_POLICY:
        words[0] = request->args.policy.generation;
        words[1] = request->args.policy.revision;
        words[2] = request->args.policy.enable;
        if (words[0] == 0 || words[2] > 1) return SHUTTER_WIRE_ARGUMENT;
        break;
    case SHUTTER_WIRE_QUERY:
        words[0] = request->args.query.mode;
        if (words[0] > 1) return SHUTTER_WIRE_ARGUMENT;
        break;
    case SHUTTER_WIRE_COPY:
        words[0] = request->args.copy.generation;
        words[1] = request->args.copy.revision;
        words[2] = request->args.copy.offset;
        words[3] = request->args.copy.length;
        if (words[0] == 0 || words[3] == 0 || words[3] > MAX_COPY ||
            words[2] > MAX_ENCODED || words[3] > MAX_ENCODED - words[2])
            return SHUTTER_WIRE_ARGUMENT;
        if (!request->payload) return SHUTTER_WIRE_NULL;
        if (request->payload_length != words[3]) return SHUTTER_WIRE_PAYLOAD;
        length += words[3];
        break;
    default:
        return SHUTTER_WIRE_OPERATION;
    }
    if (request->operation != SHUTTER_WIRE_COPY && request->payload_length != 0)
        return SHUTTER_WIRE_PAYLOAD;
    if (capacity < length) return SHUTTER_WIRE_CAPACITY;
    if (ranges_overlap_or_wrap(output, length, request, sizeof *request) ||
        ranges_overlap_or_wrap(output, length, written, sizeof *written) ||
        (request->operation == SHUTTER_WIRE_COPY &&
         ranges_overlap_or_wrap(output, length, request->payload, request->payload_length)))
        return SHUTTER_WIRE_OVERLAP;

    put16(output, 0x007e);
    put16(output + 2, 0);
    put32(output + 4, (uint32_t)request->operation);
    put32(output + 8, request->session);
    put32(output + 12, SHUTTER_WIRE_MAGIC_SHT2);
    put32(output + 16, request->session);
    put16(output + 20, request->correlation);
    put16(output + 22, 0); /* Single shutter slot. */
    for (size_t i = 0; i < 4; ++i) put32(output + 24 + 4 * i, words[i]);
    for (size_t i = 0; i < request->payload_length; ++i)
        output[REQUEST_HEADER + i] = request->payload[i];
    *written = length;
    return SHUTTER_WIRE_OK;
}

enum shutter_wire_error shutter_wire_decode_reply(
    const uint8_t *input, size_t length,
    const struct shutter_wire_expectation *expectation,
    struct shutter_wire_reply *reply) {
    struct shutter_wire_reply parsed = {0};
    if (!input || !expectation || !reply) return SHUTTER_WIRE_NULL;
    if (length != REPLY_BYTES) return SHUTTER_WIRE_LENGTH;
    if (get16(input) != 0x807eu || get16(input + 4) != 24)
        return SHUTTER_WIRE_HEADER;
    if (get16(input + 2) != 0) return SHUTTER_WIRE_RESERVED;
    if (!valid_session(expectation->session)) return SHUTTER_WIRE_SESSION;
    if (expectation->correlation == 0 || expectation->correlation == UINT16_MAX)
        return SHUTTER_WIRE_CORRELATION;
    if (expectation->operation < SHUTTER_WIRE_BIND ||
        expectation->operation > SHUTTER_WIRE_COPY) return SHUTTER_WIRE_OPERATION;
    parsed.correlation = get16(input + 6);
    parsed.session = get32(input + 8);
    uint32_t operation = get32(input + 12);
    parsed.phase = get32(input + 16);
    for (size_t i = 0; i < 5; ++i) parsed.fields[i] = get32(input + 20 + 4 * i);
    if (parsed.session != expectation->session ||
        operation != (uint32_t)expectation->operation ||
        parsed.correlation != expectation->correlation) return SHUTTER_WIRE_MISMATCH;
    if (parsed.phase > 7) return SHUTTER_WIRE_PHASE;
    parsed.operation = expectation->operation;
    *reply = parsed;
    return SHUTTER_WIRE_OK;
}
