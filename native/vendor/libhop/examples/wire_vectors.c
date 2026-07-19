// Independent native consumer for the committed deterministic wire corpus. This file uses only the
// public C ABI and never calls Rust vector constructors.

#include "hop.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    META_ID = 29,
    META_CONTENT_ID = 61,
    META_RECOGNITION_TAG = 93,
    META_RECOGNITION_EPHEMERAL = 109,
    META_MAILBOX_PRESENT = 141,
    META_MAILBOX = 142,
    META_INTEGRITY_KIND = 144,
    META_SIGNATURE_LEN = 145,
    META_SIGNATURE = 147,
};

static void fail(const char *vector, const char *message) {
    fprintf(stderr, "FAIL: %s: %s\n", vector ? vector : "corpus", message);
    exit(1);
}

static char *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) fail(NULL, "cannot open corpus");
    if (fseek(file, 0, SEEK_END) != 0) fail(NULL, "cannot seek corpus");
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) fail(NULL, "cannot size corpus");
    char *data = malloc((size_t)size + 1);
    if (!data) fail(NULL, "out of memory reading corpus");
    if (fread(data, 1, (size_t)size, file) != (size_t)size) fail(NULL, "cannot read corpus");
    if (fclose(file) != 0) fail(NULL, "cannot close corpus");
    data[size] = '\0';
    *length = (size_t)size;
    return data;
}

static const char *skip_space(const char *cursor, const char *end) {
    while (cursor < end && isspace((unsigned char)*cursor)) cursor++;
    return cursor;
}

static const char *object_end(const char *start, const char *limit) {
    unsigned depth = 0;
    bool quoted = false;
    bool escaped = false;
    for (const char *cursor = start; cursor < limit; cursor++) {
        if (quoted) {
            if (escaped) {
                escaped = false;
            } else if (*cursor == '\\') {
                escaped = true;
            } else if (*cursor == '"') {
                quoted = false;
            }
            continue;
        }
        if (*cursor == '"') {
            quoted = true;
        } else if (*cursor == '{') {
            depth++;
        } else if (*cursor == '}' && --depth == 0) {
            return cursor + 1;
        }
    }
    return NULL;
}

static const char *field_value(const char *start, const char *end, const char *key) {
    char pattern[96];
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (written < 0 || (size_t)written >= sizeof(pattern)) fail(NULL, "field name is too long");
    const char *cursor = start;
    while ((cursor = strstr(cursor, pattern)) != NULL && cursor < end) {
        cursor += (size_t)written;
        cursor = skip_space(cursor, end);
        if (cursor < end && *cursor == ':') return skip_space(cursor + 1, end);
    }
    return NULL;
}

static char *string_field(const char *start, const char *end, const char *key, bool nullable) {
    const char *value = field_value(start, end, key);
    if (!value) fail(NULL, "required field is missing");
    if (nullable && (size_t)(end - value) >= 4 && memcmp(value, "null", 4) == 0) return NULL;
    if (*value != '"') fail(NULL, "string field is not a string");
    const char *close = value + 1;
    while (close < end && *close != '"') {
        if (*close == '\\') fail(NULL, "escaped strings are unsupported in vector metadata");
        close++;
    }
    if (close == end) fail(NULL, "unterminated string field");
    size_t length = (size_t)(close - value - 1);
    char *result = malloc(length + 1);
    if (!result) fail(NULL, "out of memory reading field");
    memcpy(result, value + 1, length);
    result[length] = '\0';
    return result;
}

static uint64_t uint_field(const char *start, const char *end, const char *key) {
    const char *value = field_value(start, end, key);
    if (!value) fail(NULL, "required integer field is missing");
    errno = 0;
    char *parsed_end = NULL;
    uint64_t parsed = strtoull(value, &parsed_end, 10);
    if (errno != 0 || parsed_end == value || parsed_end > end) fail(NULL, "invalid integer field");
    return parsed;
}

static bool bool_field(const char *start, const char *end, const char *key) {
    const char *value = field_value(start, end, key);
    if (!value) fail(NULL, "required boolean field is missing");
    if ((size_t)(end - value) >= 4 && memcmp(value, "true", 4) == 0) return true;
    if ((size_t)(end - value) >= 5 && memcmp(value, "false", 5) == 0) return false;
    fail(NULL, "invalid boolean field");
    return false;
}

static uint8_t nibble(char value) {
    if (value >= '0' && value <= '9') return (uint8_t)(value - '0');
    if (value >= 'a' && value <= 'f') return (uint8_t)(value - 'a' + 10);
    fail(NULL, "invalid lowercase hex");
    return 0;
}

static uint8_t *decode_hex(const char *hex, size_t *length) {
    size_t digits = strlen(hex);
    if ((digits & 1U) != 0) fail(NULL, "odd-length hex field");
    *length = digits / 2;
    uint8_t *bytes = malloc(*length ? *length : 1);
    if (!bytes) fail(NULL, "out of memory decoding hex");
    for (size_t index = 0; index < *length; index++) {
        bytes[index] = (uint8_t)((nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]));
    }
    return bytes;
}

static uint16_t read_le16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t read_le64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (unsigned index = 0; index < 8; index++) value |= (uint64_t)bytes[index] << (index * 8);
    return value;
}

static void check_fixed_hex(const char *name, const char *hex, const uint8_t *actual, size_t width) {
    size_t expected_length = 0;
    uint8_t *expected = decode_hex(hex, &expected_length);
    if (expected_length == 0) {
        for (size_t index = 0; index < width; index++) {
            if (actual[index] != 0) fail(name, "non-applicable metadata is not zero-filled");
        }
    } else if (expected_length != width || memcmp(actual, expected, width) != 0) {
        fail(name, "fixed metadata bytes differ from corpus");
    }
    free(expected);
}

static uint8_t integrity_code(const char *name, const char *kind) {
    if (strcmp(kind, "Ed25519Signature") == 0) return 0;
    if (strcmp(kind, "PrivateWireId") == 0) return 1;
    if (strcmp(kind, "VaccineId") == 0) return 2;
    fail(name, "unknown integrity kind");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s core/hop-core/vectors/bundle-v9.json\n", argv[0]);
        return 2;
    }
    size_t document_length = 0;
    char *document = read_file(argv[1], &document_length);
    const char *document_end = document + document_length;
    if (uint_field(document, document_end, "bundle_version") != 10) {
        fail(NULL, "expected bundle corpus version 10");
    }
    const char *bundles = strstr(document, "\"bundles\"");
    const char *array = bundles ? strchr(bundles, '[') : NULL;
    if (!array) fail(NULL, "bundles array is missing");

    size_t checked = 0;
    size_t private_count = 0;
    size_t private_init = 0;
    size_t private_message = 0;
    size_t private_ack = 0;
    size_t private_without_mailbox = 0;
    size_t stamped_count = 0;
    const char *cursor = array + 1;
    for (;;) {
        cursor = skip_space(cursor, document_end);
        if (cursor < document_end && *cursor == ',') cursor = skip_space(cursor + 1, document_end);
        if (cursor >= document_end || *cursor == ']') break;
        if (*cursor != '{') fail(NULL, "invalid bundles array entry");
        const char *end = object_end(cursor, document_end);
        if (!end) fail(NULL, "unterminated bundle object");

        char *name = string_field(cursor, end, "name", false);
        char *bytes_hex = string_field(cursor, end, "bytes_hex", false);
        char *ciphertext_hex = string_field(cursor, end, "ciphertext_hex", false);
        char *id_hex = string_field(cursor, end, "id_hex", false);
        char *content_id_hex = string_field(cursor, end, "private_content_id_hex", false);
        char *tag_hex = string_field(cursor, end, "recognition_tag_hex", false);
        char *ephemeral_hex = string_field(cursor, end, "recognition_ephemeral_hex", false);
        char *mailbox_hex = string_field(cursor, end, "private_mailbox_hex", false);
        char *signature_hex = string_field(cursor, end, "signature_hex", false);
        char *access_hex = string_field(cursor, end, "access_hex", false);
        char *integrity = string_field(cursor, end, "integrity_kind", false);
        char *private_inner = string_field(cursor, end, "private_inner_variant", true);

        size_t bytes_length = 0;
        size_t ciphertext_length = 0;
        size_t id_length = 0;
        size_t signature_length = 0;
        size_t access_length = 0;
        uint8_t *bytes = decode_hex(bytes_hex, &bytes_length);
        uint8_t *ciphertext = decode_hex(ciphertext_hex, &ciphertext_length);
        uint8_t *id = decode_hex(id_hex, &id_length);
        uint8_t *signature = decode_hex(signature_hex, &signature_length);
        uint8_t *access = decode_hex(access_hex, &access_length);
        if (id_length != 32 || signature_length > 64) fail(name, "invalid ID or signature length");
        bool access_present = bool_field(cursor, end, "access_present");
        if (access_length == 0 || access[0] != (uint8_t)access_present ||
            (!access_present && access_length != 1)) {
            fail(name, "carriage-stamp access layout differs from corpus metadata");
        }
        if (access_present) stamped_count++;

        uint8_t metadata[HOP_WIRE_BUNDLE_METADATA_LEN];
        memset(metadata, 0xa5, sizeof(metadata));
        if (!hop_validate_wire_bundle(bytes, bytes_length, metadata, sizeof(metadata))) {
            fail(name, "public C ABI rejected committed canonical bytes");
        }
        if (metadata[0] != uint_field(cursor, end, "version") ||
            metadata[1] != uint_field(cursor, end, "destination_code") ||
            metadata[2] != (uint8_t)bool_field(cursor, end, "private") ||
            metadata[3] != (uint8_t)bool_field(cursor, end, "is_ack") ||
            read_le32(metadata + 4) != bytes_length ||
            read_le32(metadata + 8) != ciphertext_length ||
            read_le16(metadata + 12) != uint_field(cursor, end, "copies") ||
            metadata[14] != uint_field(cursor, end, "hops") ||
            metadata[15] != uint_field(cursor, end, "trace_len") ||
            read_le64(metadata + 16) != uint_field(cursor, end, "created_at") ||
            read_le32(metadata + 24) != uint_field(cursor, end, "lifetime_ms") ||
            metadata[28] != uint_field(cursor, end, "hop_limit")) {
            fail(name, "decoded envelope metadata differs from corpus");
        }
        if (memcmp(metadata + META_ID, id, 32) != 0) fail(name, "computed ID differs from corpus");
        check_fixed_hex(name, content_id_hex, metadata + META_CONTENT_ID, 32);
        check_fixed_hex(name, tag_hex, metadata + META_RECOGNITION_TAG, 16);
        check_fixed_hex(name, ephemeral_hex, metadata + META_RECOGNITION_EPHEMERAL, 32);
        bool mailbox_present = bool_field(cursor, end, "private_mailbox_present");
        if (metadata[META_MAILBOX_PRESENT] != (uint8_t)mailbox_present) {
            fail(name, "mailbox presence differs from corpus");
        }
        check_fixed_hex(name, mailbox_hex, metadata + META_MAILBOX, 2);
        if (metadata[META_INTEGRITY_KIND] != integrity_code(name, integrity)) {
            fail(name, "integrity mode differs from corpus");
        }
        if (read_le16(metadata + META_SIGNATURE_LEN) != signature_length ||
            memcmp(metadata + META_SIGNATURE, signature, signature_length) != 0) {
            fail(name, "verified signature differs from corpus");
        }

        uint8_t *noncanonical = malloc(bytes_length + 1);
        if (!noncanonical) fail(name, "out of memory building rejection probe");
        memcpy(noncanonical, bytes, bytes_length);
        noncanonical[bytes_length] = 0;
        if (hop_validate_wire_bundle(noncanonical, bytes_length + 1, metadata, sizeof(metadata))) {
            fail(name, "non-canonical trailing byte was accepted");
        }

        if (bool_field(cursor, end, "private")) {
            private_count++;
            if (!private_inner) fail(name, "private vector lacks an inner payload variant");
            if (strcmp(private_inner, "SessionInit") == 0) private_init++;
            else if (strcmp(private_inner, "SessionMessage") == 0) private_message++;
            else if (strcmp(private_inner, "Ack") == 0) private_ack++;
            else fail(name, "unexpected private inner payload variant");
            if (!mailbox_present) private_without_mailbox++;
        }

        free(noncanonical);
        free(access);
        free(signature);
        free(id);
        free(ciphertext);
        free(bytes);
        free(private_inner);
        free(integrity);
        free(access_hex);
        free(signature_hex);
        free(mailbox_hex);
        free(ephemeral_hex);
        free(tag_hex);
        free(content_id_hex);
        free(id_hex);
        free(ciphertext_hex);
        free(bytes_hex);
        free(name);
        checked++;
        cursor = end;
    }

    free(document);
    if (checked != 30) fail(NULL, "expected 30 complete bundle vectors");
    if (stamped_count != 1) fail(NULL, "expected one stamped complete bundle vector");
    if (private_count != 4 || private_init != 1 || private_message != 2 || private_ack != 1 ||
        private_without_mailbox != 1) {
        fail(NULL, "private full-bundle coverage is incomplete");
    }
    printf("native wire vectors: %zu complete bundles, %zu private, %zu stamped, canonical C ABI validation passed\n",
           checked, private_count, stamped_count);
    return 0;
}
