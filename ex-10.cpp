#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Constants for SHA-1 algorithm
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

// SHA-1 functions
#define SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define SHA1_BLK(i) (block[(i) & 15] = SHA1_ROL(block[(i - 3) & 15] ^ block[(i - 8) & 15] ^ block[(i - 14) & 15] ^ block[i & 15], 1))

// SHA-1 context structure
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[SHA1_BLOCK_SIZE];
} SHA1_CTX;

// SHA-1 functions prototypes
void sha1_transform(uint32_t state[5], const uint8_t buffer[SHA1_BLOCK_SIZE]);
void sha1_init(SHA1_CTX *context);
void sha1_update(SHA1_CTX *context, const uint8_t *data, uint32_t len);
void sha1_final(uint8_t digest[SHA1_DIGEST_SIZE], SHA1_CTX *context);
void sha1_transform(uint32_t state[5], const uint8_t buffer[SHA1_BLOCK_SIZE]);

// SHA-1 initialization constants
static const uint32_t sha1_init_state[5] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

// Initialize SHA-1 context
void sha1_init(SHA1_CTX *context) {
    context->count[0] = context->count[1] = 0;
    memcpy(context->state, sha1_init_state, sizeof(context->state));
}

// SHA-1 core transformation
void sha1_transform(uint32_t state[5], const uint8_t buffer[SHA1_BLOCK_SIZE]) {
    uint32_t a, b, c, d, e, temp;
    uint32_t block[80];

    // Copy state[] to working vars
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    // Copy the buffer to the 512-bit block
    memcpy(block, buffer, SHA1_BLOCK_SIZE);

    // Extend the 16 32-bit words into 80 32-bit words
    for (int i = 16; i < 80; i++) {
        block[i] = SHA1_ROL(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
    }

    // Main loop
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            temp = SHA1_ROL(a, 5) + ((b & c) | ((~b) & d)) + e + block[i] + 0x5A827999;
        } else if (i < 40) {
            temp = SHA1_ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = SHA1_ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + block[i] + 0x8F1BBCDC;
        } else {
            temp = SHA1_ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0xCA62C1D6;
        }
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = temp;
    }

    // Add this chunk's hash to result so far
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    // Zeroize sensitive information
    memset(block, 0, sizeof(block));
}

// SHA-1 update context with input data
void sha1_update(SHA1_CTX *context, const uint8_t *data, uint32_t len) {
    uint32_t i, index, part_len;

    index = (uint32_t)((context->count[1] >> 3) & 0x3F);

    if ((context->count[1] += len << 3) < (len << 3)) {
        context->count[0]++;
    }
    context->count[0] += (len >> 29);

    part_len = SHA1_BLOCK_SIZE - index;

    if (len >= part_len) {
        memcpy(&context->buffer[index], data, part_len);
        sha1_transform(context->state, context->buffer);

        for (i = part_len; i + SHA1_BLOCK_SIZE <= len; i += SHA1_BLOCK_SIZE) {
            sha1_transform(context->state, &data[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&context->buffer[index], &data[i], len - i);
}

// SHA-1 final digest
void sha1_final(uint8_t digest[SHA1_DIGEST_SIZE], SHA1_CTX *context) {
    uint8_t finalcount[8];
    uint8_t c, len;

    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }

    c = 0200;
    sha1_update(context, &c, 1);

    while ((context->count[1] & 504) != 448) {
        c = 0000;
        sha1_update(context, &c, 1);
    }

    sha1_update(context, finalcount, 8); // Append length (before padding)

    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
        digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    // Zeroize sensitive information
    memset(finalcount, 0, sizeof(finalcount));
    memset(context, 0, sizeof(*context));
}

int main() {
    char input[100];
    uint8_t digest[SHA1_DIGEST_SIZE];
    SHA1_CTX context;

    // Prompt user for input
    printf("Enter a string to hash with SHA-1: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0'; // Remove newline if present

    // Initialize SHA-1 context
    sha1_init(&context);

    // Update context with user input
    sha1_update(&context, (uint8_t *)input, strlen(input));

    // Finalize the SHA-1 computation and get the digest
    sha1_final(digest, &context);

    // Print the SHA-1 digest
    printf("SHA-1 Digest: ");
    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}

