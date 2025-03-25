#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Use a 32-bit type */
typedef uint32_t u32;

/* Represent a 64-bit value as an array of 2 32-bit values:
   [0] - high 32 bits, [1] - low 32 bits */
typedef u32 uint64_emul[2];

/* Function prototypes */
void uint64_to_bytes(const uint64_emul value, unsigned char *bytes);
void bytes_to_uint64(const unsigned char *bytes, uint64_emul result);
void copy64(uint64_emul dst, const uint64_emul src);
void add64(uint64_emul result, const uint64_emul a, const uint64_emul b);
void shr64(uint64_emul result, const uint64_emul a, int n);
void shl64(uint64_emul result, const uint64_emul a, int n);
void ror64(uint64_emul result, const uint64_emul a, int n);
void and64(uint64_emul result, const uint64_emul a, const uint64_emul b);
void or64(uint64_emul result, const uint64_emul a, const uint64_emul b);
void xor64(uint64_emul result, const uint64_emul a, const uint64_emul b);
void not64(uint64_emul result, const uint64_emul a);

void Ch(uint64_emul result, const uint64_emul x, const uint64_emul y, const uint64_emul z);
void Maj(uint64_emul result, const uint64_emul x, const uint64_emul y, const uint64_emul z);
void Sigma0(uint64_emul result, const uint64_emul x);
void Sigma1(uint64_emul result, const uint64_emul x);
void sigma0(uint64_emul result, const uint64_emul x);
void sigma1(uint64_emul result, const uint64_emul x);

void init_k(uint64_emul k, int i);
void sha512_transform(const unsigned char *data);
void increment_counter(uint64_emul count, uint64_emul count2, uint32_t bits);
void sha512_init(void);
void sha512_update(const unsigned char *data, unsigned int len);
void sha512_final(unsigned char *hash);
void sha512(const unsigned char *data, unsigned int len, unsigned char *hash);
void print_hash(unsigned char *hash);
void test_known_hashes(void);

/* SHA-512 constants */
static const u32 K_high[80] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f,
    0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
    0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4,
    0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c
};

static const u32 K_low[80] = {
    0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc,
    0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
    0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2,
    0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
    0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
    0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
    0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4,
    0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
    0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df,
    0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
    0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30,
    0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
    0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8,
    0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
    0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
    0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
    0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178,
    0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
    0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c,
    0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817
};

static const u32 H0_high[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const u32 H0_low[8] = {
    0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
    0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179
};

/* Global variables for SHA-512 computation */

/* Instead of an array of structures for 16 words, we use an array of 32-bit values.
   Each 64-bit word consists of 2 u32 values. */
static u32 g_w_buffer[16 * 2];
#define G_W(i) (((uint64_emul *)g_w_buffer)[(i)])

static uint64_emul g_temp1, g_temp2;
static uint64_emul g_a, g_b, g_c, g_d, g_e, g_f, g_g, g_h;
static uint64_emul g_s0, g_s1, g_ch, g_maj;

/* Global variables for SHA-512 context */
static uint64_emul sha_state[8];
static uint64_emul sha_count[2];
static unsigned char sha_buffer[128];

void uint64_to_bytes(const uint64_emul value, unsigned char *bytes) {
    bytes[0] = (value[0] >> 24) & 0xFF;
    bytes[1] = (value[0] >> 16) & 0xFF;
    bytes[2] = (value[0] >> 8) & 0xFF;
    bytes[3] = value[0] & 0xFF;
    bytes[4] = (value[1] >> 24) & 0xFF;
    bytes[5] = (value[1] >> 16) & 0xFF;
    bytes[6] = (value[1] >> 8) & 0xFF;
    bytes[7] = value[1] & 0xFF;
}

void bytes_to_uint64(const unsigned char *bytes, uint64_emul result) {
    result[0] = ((u32)bytes[0] << 24) | ((u32)bytes[1] << 16) |
                ((u32)bytes[2] << 8)  | ((u32)bytes[3]);
    result[1] = ((u32)bytes[4] << 24) | ((u32)bytes[5] << 16) |
                ((u32)bytes[6] << 8)  | ((u32)bytes[7]);
}

void copy64(uint64_emul dst, const uint64_emul src) {
    dst[0] = src[0];
    dst[1] = src[1];
}

void add64(uint64_emul result, const uint64_emul a, const uint64_emul b) {
    u32 low, carry;
    low = a[1] + b[1];
    carry = (low < a[1]) ? 1U : 0U;
    result[0] = a[0] + b[0] + carry;
    result[1] = low;
}

void shr64(uint64_emul result, const uint64_emul a, int n) {
    if(n >= 64) {
        result[0] = 0;
        result[1] = 0;
        return;
    }
    if(n >= 32) {
        result[1] = a[0] >> (n - 32);
        result[0] = 0;
    } else if(n > 0) {
        u32 shift_amt = 32 - n;
        result[1] = (a[1] >> n) | (a[0] << shift_amt);
        result[0] = a[0] >> n;
    } else {
        result[0] = a[0];
        result[1] = a[1];
    }
}

void shl64(uint64_emul result, const uint64_emul a, int n) {
    if(n >= 64) {
        result[0] = 0;
        result[1] = 0;
        return;
    }
    if(n >= 32) {
        result[0] = a[1] << (n - 32);
        result[1] = 0;
    } else if(n > 0) {
        u32 shift_amt = 32 - n;
        result[0] = (a[0] << n) | (a[1] >> shift_amt);
        result[1] = a[1] << n;
    } else {
        result[0] = a[0];
        result[1] = a[1];
    }
}

void ror64(uint64_emul result, const uint64_emul a, int n) {
    uint64_emul right, left;
    int shift;
    n = n % 64;
    if(n == 0) {
        result[0] = a[0];
        result[1] = a[1];
        return;
    }
    shift = 64 - n;
    shr64(right, a, n);
    shl64(left, a, shift);
    result[0] = right[0] | left[0];
    result[1] = right[1] | left[1];
}

void and64(uint64_emul result, const uint64_emul a, const uint64_emul b) {
    result[0] = a[0] & b[0];
    result[1] = a[1] & b[1];
}

void or64(uint64_emul result, const uint64_emul a, const uint64_emul b) {
    result[0] = a[0] | b[0];
    result[1] = a[1] | b[1];
}

void xor64(uint64_emul result, const uint64_emul a, const uint64_emul b) {
    result[0] = a[0] ^ b[0];
    result[1] = a[1] ^ b[1];
}

void not64(uint64_emul result, const uint64_emul a) {
    result[0] = ~a[0];
    result[1] = ~a[1];
}

void Ch(uint64_emul result, const uint64_emul x, const uint64_emul y, const uint64_emul z) {
    uint64_emul temp1, temp2, notx;
    not64(notx, x);
    and64(temp1, x, y);
    and64(temp2, notx, z);
    xor64(result, temp1, temp2);
}

void Maj(uint64_emul result, const uint64_emul x, const uint64_emul y, const uint64_emul z) {
    uint64_emul temp1, temp2, temp3;
    and64(temp1, x, y);
    and64(temp2, x, z);
    and64(temp3, y, z);
    xor64(temp1, temp1, temp2);
    xor64(result, temp1, temp3);
}

void Sigma0(uint64_emul result, const uint64_emul x) {
    uint64_emul temp1, temp2, temp3;
    ror64(temp1, x, 28);
    ror64(temp2, x, 34);
    ror64(temp3, x, 39);
    xor64(temp1, temp1, temp2);
    xor64(result, temp1, temp3);
}

void Sigma1(uint64_emul result, const uint64_emul x) {
    uint64_emul temp1, temp2, temp3;
    ror64(temp1, x, 14);
    ror64(temp2, x, 18);
    ror64(temp3, x, 41);
    xor64(temp1, temp1, temp2);
    xor64(result, temp1, temp3);
}

void sigma0(uint64_emul result, const uint64_emul x) {
    uint64_emul temp1, temp2, temp3;
    ror64(temp1, x, 1);
    ror64(temp2, x, 8);
    shr64(temp3, x, 7);
    xor64(temp1, temp1, temp2);
    xor64(result, temp1, temp3);
}

void sigma1(uint64_emul result, const uint64_emul x) {
    uint64_emul temp1, temp2, temp3;
    ror64(temp1, x, 19);
    ror64(temp2, x, 61);
    shr64(temp3, x, 6);
    xor64(temp1, temp1, temp2);
    xor64(result, temp1, temp3);
}

void init_k(uint64_emul k, int i) {
    k[0] = K_high[i];
    k[1] = K_low[i];
}

void sha512_transform(const unsigned char *data) {
    int i, idx, idx_2, idx_7, idx_15, idx_16;
    uint64_emul wi, k;
    /* Convert first 16 words */
    for (i = 0; i < 16; i++) {
        bytes_to_uint64(data + (i * 8), G_W(i));
    }
    copy64(g_a, sha_state[0]);
    copy64(g_b, sha_state[1]);
    copy64(g_c, sha_state[2]);
    copy64(g_d, sha_state[3]);
    copy64(g_e, sha_state[4]);
    copy64(g_f, sha_state[5]);
    copy64(g_g, sha_state[6]);
    copy64(g_h, sha_state[7]);
    
    for (i = 0; i < 80; i++) {
        if (i < 16) {
            copy64(wi, G_W(i));
        } else {
            idx = i & 0xF;
            idx_2 = (i - 2) & 0xF;
            idx_7 = (i - 7) & 0xF;
            idx_15 = (i - 15) & 0xF;
            idx_16 = (i - 16) & 0xF;
            sigma1(g_s1, G_W(idx_2));
            sigma0(g_s0, G_W(idx_15));
            add64(g_temp1, g_s1, G_W(idx_7));
            add64(g_temp2, g_temp1, g_s0);
            add64(G_W(idx), g_temp2, G_W(idx_16));
            copy64(wi, G_W(idx));
        }
        init_k(k, i);
        Sigma1(g_s1, g_e);
        Ch(g_ch, g_e, g_f, g_g);
        add64(g_temp1, g_h, g_s1);
        add64(g_temp1, g_temp1, g_ch);
        add64(g_temp1, g_temp1, k);
        add64(g_temp1, g_temp1, wi);
        Sigma0(g_s0, g_a);
        Maj(g_maj, g_a, g_b, g_c);
        add64(g_temp2, g_s0, g_maj);
        copy64(g_h, g_g);
        copy64(g_g, g_f);
        copy64(g_f, g_e);
        add64(g_e, g_d, g_temp1);
        copy64(g_d, g_c);
        copy64(g_c, g_b);
        copy64(g_b, g_a);
        add64(g_a, g_temp1, g_temp2);
    }
    
    add64(sha_state[0], sha_state[0], g_a);
    add64(sha_state[1], sha_state[1], g_b);
    add64(sha_state[2], sha_state[2], g_c);
    add64(sha_state[3], sha_state[3], g_d);
    add64(sha_state[4], sha_state[4], g_e);
    add64(sha_state[5], sha_state[5], g_f);
    add64(sha_state[6], sha_state[6], g_g);
    add64(sha_state[7], sha_state[7], g_h);
}

void increment_counter(uint64_emul count, uint64_emul count2, uint32_t bits) {
    uint64_emul bits_low, bits_high, new_low, one;
    one[0] = 0;
    one[1] = 1;
    
    bits_low[0] = 0;
    bits_low[1] = bits & 0xFFFFFFFFU;
    
    bits_high[0] = 0;
    /* For messages shorter than 2^32 bits */
    bits_high[1] = 0;
    
    add64(new_low, count, bits_low);
    if(new_low[0] < count[0] ||
       (new_low[0] == count[0] && new_low[1] < count[1])) {
        add64(count2, count2, one);
    }
    copy64(count, new_low);
    add64(count2, count2, bits_high);
}

void sha512_init(void) {
    int i;
    sha_count[0][0] = sha_count[0][1] = 0;
    sha_count[1][0] = sha_count[1][1] = 0;
    for (i = 0; i < 8; i++) {
        sha_state[i][0] = H0_high[i];
        sha_state[i][1] = H0_low[i];
    }
}

void sha512_update(const unsigned char *data, unsigned int len) {
    unsigned int i, pos, space;
    pos = ((unsigned int)(sha_count[0][1] >> 3)) & 0x7F;
    increment_counter(sha_count[0], sha_count[1], ((u32)len << 3));
    space = 128 - pos;
    if (len >= space) {
        memcpy(sha_buffer + pos, data, space);
        sha512_transform(sha_buffer);
        for (i = space; i + 127 < len; i += 128) {
            sha512_transform(data + i);
        }
        pos = 0;
        data += space;
        len -= space;
    }
    memcpy(sha_buffer + pos, data, len);
}

void sha512_final(unsigned char *hash) {
    unsigned int pos;
    int i;
    pos = ((unsigned int)(sha_count[0][1] >> 3)) & 0x7F;
    sha_buffer[pos++] = 0x80;
    if (pos > 112) {
        memset(sha_buffer + pos, 0, 128 - pos);
        sha512_transform(sha_buffer);
        pos = 0;
    }
    memset(sha_buffer + pos, 0, 112 - pos);
    uint64_to_bytes(sha_count[1], sha_buffer + 112);
    uint64_to_bytes(sha_count[0], sha_buffer + 120);
    sha512_transform(sha_buffer);
    for (i = 0; i < 8; i++) {
        uint64_to_bytes(sha_state[i], hash + (i * 8));
    }
}

void sha512(const unsigned char *data, unsigned int len, unsigned char *hash) {
    sha512_init();
    sha512_update(data, len);
    sha512_final(hash);
}

void print_hash(unsigned char *hash) {
    int i;
    for (i = 0; i < 64; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

/* Convert one PETSCII character to ASCII.
   This simple conversion assumes:
   - PETSCII lowercase letters are in the range 0xC1-0xDA;
     converting them to ASCII lowercase by: ascii = pet - 0x60.
   - PETSCII uppercase letters are in the range 0x41-0x5A;
     converting them to lowercase by adding 0x20.
   Other characters are left unchanged.
*/
unsigned char petscii_to_ascii(unsigned char c) {
    if (c >= 0xC1 && c <= 0xDA)
        return c - 0x60;
    if (c >= 0x41 && c <= 0x5A)
        return c + 0x20;
    return c;
}

/* Global buffers to reduce local variable usage */
static char converted_buf[256];  /* Buffer for PETSCII→ASCII conversion */
static char generated_buf[129];  /* Buffer for hex-string of hash */

void test_known_hashes(void) {
    int i, j, len;
    const char *input, *expected;
    unsigned char hash[64];

    /* Test vectors: expected hashes are for ASCII strings in lower case */
    static const char *test_vectors[3][2] = {
        {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"}
    };

    for (i = 0; i < 3; i++) {
        input = test_vectors[i][0];
        expected = test_vectors[i][1];

        printf("Test %d:\n", i + 1);
        printf("Input (PETSCII): '%s'\n", input);

        len = (int)strlen(input);
        /* Convert input from PETSCII to ASCII using the global buffer */
        for (j = 0; j < len; j++) {
            converted_buf[j] = petscii_to_ascii((unsigned char)input[j]);
        }
        converted_buf[len] = '\0';
        printf("Converted (ASCII): '%s'\n", converted_buf);

        /* Compute SHA-512 on the converted string */
        sha512((const unsigned char*)converted_buf, (unsigned int)len, hash);

        printf("Hash: ");
        print_hash(hash);

        /* Generate hex string using global buffer */
        memset(generated_buf, 0, sizeof(generated_buf));
        for (j = 0; j < 64; j++) {
            sprintf(generated_buf + j * 2, "%02x", hash[j]);
        }

        if (strcmp(generated_buf, expected) == 0) {
            printf("Match\n");
        } else {
            printf("Mismatch\n");
            printf("Expected: %s\n", expected);
        }
        printf("\n");
    }
}


int main(void) {
    //const char *str;
    //unsigned char hash[64];
    
    test_known_hashes();
    
    //str = "Example string for SHA-512";
    //sha512((const unsigned char*)str, (unsigned int)strlen(str), hash);
    
    //printf("\nUser string: %s\n", str);
    //printf("SHA-512: ");
    //print_hash(hash);
    
    return 0;
}
