#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Constants for MD5Transform routine
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

typedef unsigned char BYTE;
typedef unsigned int  UINT4;

typedef struct {
    UINT4 state[4];    // state (ABCD)
    UINT4 count[2];    // number of bits, modulo 2^64 (lsb first)
    BYTE buffer[64];   // input buffer
} MD5_CTX;

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, BYTE *input, unsigned int inputLen);
void MD5Final(BYTE digest[16], MD5_CTX *context);
void MD5Transform(UINT4 state[4], BYTE block[64]);
void Encode(BYTE *output, UINT4 *input, unsigned int len);
void Decode(UINT4 *output, BYTE *input, unsigned int len);
void MD5_memcpy(BYTE *output, BYTE *input, unsigned int len);
void MD5_memset(BYTE *output, int value, unsigned int len);

BYTE PADDING[64] = { 0x80 };

void MD5Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;

    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

void MD5Update(MD5_CTX *context, BYTE *input, unsigned int inputLen) {
    unsigned int i, index, partLen;

    index = (unsigned int)((context->count[0] >> 3) & 0x3F);

    if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3)) {
        context->count[1]++;
    }
    context->count[1] += ((UINT4)inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen) {
        MD5_memcpy((BYTE *)&context->buffer[index], (BYTE *)input, partLen);
        MD5Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64) {
            MD5Transform(context->state, &input[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    MD5_memcpy((BYTE *)&context->buffer[index], (BYTE *)&input[i], inputLen - i);
}

void MD5Final(BYTE digest[16], MD5_CTX *context) {
    BYTE bits[8];
    unsigned int index, padLen;

    Encode(bits, context->count, 8);

    index = (unsigned int)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, PADDING, padLen);
    MD5Update(context, bits, 8);

    Encode(digest, context->state, 16);

    MD5_memset((BYTE *)context, 0, sizeof(*context));
}

void MD5Transform(UINT4 state[4], BYTE block[64]) {
    UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    Decode(x, block, 64);

    /* Round 1 */
    #define FF(a, b, c, d, x, s, ac) { \
        (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }
    /* Round 2 */
    #define GG(a, b, c, d, x, s, ac) { \
        (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }
    /* Round 3 */
    #define HH(a, b, c, d, x, s, ac) { \
        (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }
    /* Round 4 */
    #define II(a, b, c, d, x, s, ac) { \
        (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }

    /* Define auxiliary functions */
    #define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
    #define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
    #define H(x, y, z) ((x) ^ (y) ^ (z))
    #define I(x, y, z) ((y) ^ ((x) | (~z)))
    #define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

    /* Perform the transformation */
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF (c, d, a, b, x[ 2], S13, 0x242070db);
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF (c, d, a, b, x[ 6], S13, 0xa8304613);
    FF (b, c, d, a, x[ 7], S14, 0xfd469501);
    FF (a, b, c, d, x[ 8], S11, 0x698098d8);
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF (c, d, a, b, x[10], S13, 0xffff5bb1);
    FF (b, c, d, a, x[11], S14, 0x895cd7be);
    FF (a, b, c, d, x[12], S11, 0x6b901122);
    FF (d, a, b, c, x[13], S12, 0xfd987193);
    FF (c, d, a, b, x[14], S13, 0xa679438e);
    FF (b, c, d, a, x[15], S14, 0x49b40821);

    GG (a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG (d, a, b, c, x[ 6], S22, 0xc040b340);
    GG (c, d, a, b, x[11], S23, 0x265e5a51);
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG (d, a, b, c, x[10], S22, 0x02441453);
    GG (c, d, a, b, x[15], S23, 0xd8a1e681);
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8);

    HH (a, b, c, d, x[ 9], S31, 0x21e1cde6);
    HH (d, a, b, c, x[14], S32, 0xc33707d6);
    HH (c, d, a, b, x[ 3], S33, 0xf4d50d87);
    HH (b, c, d, a, x[ 8], S34, 0x455a14ed);
    HH (a, b, c, d, x[13], S31, 0xa9e3e905);
    HH (d, a, b, c, x[ 2], S32, 0xfcefa3f8);
    HH (c, d, a, b, x[ 7], S33, 0x676f02d9);
    HH (b, c, d, a, x[12], S34, 0x8d2a4c8a);

    II (a, b, c, d, x[ 5], S41, 0xfffa3942);
    II (d, a, b, c, x[ 8], S42, 0x8771f681);
    II (c, d, a, b, x[11], S43, 0x6d9d6122);
    II (b, c, d, a, x[14], S44, 0xfde5380c);
    II (a, b, c, d, x[ 1], S41, 0xa4beea44);
    II (d, a, b, c, x[ 4], S42, 0x4bdecfa9);
    II (c, d, a, b, x[ 7], S43, 0xf6bb4b60);
    II (b, c, d, a, x[10], S44, 0xbebfbc70);
    II (a, b, c, d, x[13], S41, 0x289b7ec6);
    II (d, a, b, c, x[ 0], S42, 0xeaa127fa);
    II (c, d, a, b, x[ 3], S43, 0xd4ef3085);
    II (b, c, d, a, x[ 6], S44, 0x04881d05);
    II (a, b, c, d, x[ 9], S41, 0xd9d4d039);
    II (d, a, b, c, x[12], S42, 0xe6db99e5);
    II (c, d, a, b, x[15], S43, 0x1fa27cf8);
    II (b, c, d, a, x[ 2], S44, 0xc4ac5665);

    /* Update state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /* Zeroize sensitive information */
    MD5_memset((BYTE *)x, 0, sizeof(x));
}

void Encode(BYTE *output, UINT4 *input, unsigned int len) {
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (BYTE)(input[i] & 0xff);
        output[j+1] = (BYTE)((input[i] >> 8) & 0xff);
        output[j+2] = (BYTE)((input[i] >> 16) & 0xff);
        output[j+3] = (BYTE)((input[i] >> 24) & 0xff);
    }
}

void Decode(UINT4 *output, BYTE *input, unsigned int len) {
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
                    (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
    }
}

void MD5_memcpy(BYTE *output, BYTE *input, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        output[i] = input[i];
    }
}

void MD5_memset(BYTE *output, int value, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        output[i] = (BYTE)value;
    }
}

int main() {
    MD5_CTX context;
    BYTE digest[16];
    char input[100];

    // Prompt user for input
    printf("Enter a string to hash with MD5: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0'; // Remove newline if present

    // Initialize MD5 context
    MD5Init(&context);

    // Update context with user input
    MD5Update(&context, (BYTE *)input, strlen(input));

    // Finalize the MD5 computation and get the digest
    MD5Final(digest, &context);

    // Print the MD5 digest
    printf("MD5 Digest: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Print success message
    printf("MD5 hashing successful.\n");

    return 0;
}

