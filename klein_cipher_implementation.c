#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

// test case no: 1

const uint64_t KEY = 0x0000000000000000;
const uint64_t PLAINTEXT = 0xFFFFFFFFFFFFFFFF;
//  ciphertext should be: CDC0 B51F 1472 2BBE

// test case no: 2

//const uint64_t KEY = 0xFFFFFFFFFFFFFFFF;
//const uint64_t PLAINTEXT = 0x0000000000000000;
//  ciphertext should be: 6456 764E 8602 E154


const int Nr = 12;

const uint8_t SBOX[] = {0x7, 0x4, 0xA, 0x9, 0x1, 0xF, 0xB, 0x0, 0xC, 0x3, 0x2, 0x6, 0x8, 0xE, 0xD, 0x5};


uint8_t galois_x4_1(uint8_t temp_st) {
    int itr;
    for (itr = 7; itr >= 0; itr--) {
        if (temp_st >> itr & 0x1) {
            temp_st ^= 0x11 << (itr - 4);
        }
    }
    return temp_st;
}

uint64_t Roundkey(uint64_t text, uint64_t sk) {
    return text ^ sk;
}

uint64_t substituteNibbles(uint64_t text) {
    uint64_t res = 0;
    int itr;
    for (itr = 15; itr >= 0; itr--) {
        res = res << 4;
        res += SBOX[(text & ((uint64_t) 0xF << 4*itr)) >> 4*itr];
    }
    return res;
}

uint64_t rotateLeft(uint64_t n) {
    return ((n >> 63) & 0x1) | (n << 1);
}

uint64_t nib_rotate(uint64_t text) {
    int itr;
    for(itr = 0; itr < 16;itr++) {
        text = rotateLeft(text);
    }
    return text;
}


void gmix_column(uint64_t *r)
{
    unsigned char temp_st[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;

    for(c=0; c<4; c++)
    {
        temp_st[c] = r[c];
        h = (unsigned char)((signed char)r[c] >> 7);
        b[c] = r[c] << 1; 
        b[c] ^= 0x1B & h; 
    }

    r[0] = b[0] ^ temp_st[3] ^ temp_st[2] ^ b[1] ^ temp_st[1]; 
    r[1] = b[1] ^ temp_st[0] ^ temp_st[3] ^ b[2] ^ temp_st[2]; 
    r[2] = b[2] ^ temp_st[1] ^ temp_st[0] ^ b[3] ^ temp_st[3]; 
    r[3] = b[3] ^ temp_st[2] ^ temp_st[1] ^ b[0] ^ temp_st[0]; 
}

uint64_t colmix(uint64_t text) {
    uint64_t temp_state[8];

    temp_state[0] = (text >> 56) & 0xFF;
    temp_state[1] = (text >> 48) & 0xFF;
    temp_state[2] = (text >> 40) & 0xFF;
    temp_state[3] = (text >> 32) & 0xFF;
    temp_state[4] = (text >> 24) & 0xFF;
    temp_state[5] = (text >> 16) & 0xFF;
    temp_state[6] = (text >> 8) & 0xFF;
    temp_state[7] = (text >> 0) & 0xFF;

    gmix_column(temp_state);
    gmix_column((temp_state+4));
    

    return (
            (temp_state[0] << 56) |
            (temp_state[1] << 48) |
            (temp_state[2] << 40) |
            (temp_state[3] << 32) |
            (temp_state[4] << 24) |
            (temp_state[5] << 16) |
            (temp_state[6] << 8) |
            (temp_state[7] << 0));

}

uint64_t scheduling_key(uint64_t sk, uint8_t itr) {
    uint8_t r0 = ((uint8_t) (sk >> 56) & 0xFF);
    uint8_t r1 = ((uint8_t) (sk >> 48) & 0xFF);
    uint8_t r2 = ((uint8_t) (sk >> 40) & 0xFF);
    uint8_t r3 = ((uint8_t) (sk >> 32) & 0xFF);
    uint8_t r4 = ((uint8_t) (sk >> 24) & 0xFF);
    uint8_t r5 = ((uint8_t) (sk >> 16) & 0xFF);
    uint8_t r6 = ((uint8_t) (sk >> 8) & 0xFF);
    uint8_t r7 = ((uint8_t) sk & 0xFF);
        
    r1 ^= r5;
    r2 ^= r6;
    r3 ^= r7;
    r0 ^= r4;
    
    return (((uint64_t) r5) << 56) ^ (((uint64_t) r6) << 48) ^ (((uint64_t) (r7 ^ itr)) << 40) ^ (((uint64_t) r4) << 32)
         ^ (((uint64_t) r1) << 24)
         ^ (((uint64_t) SBOX[(r2 >> 4) & 0xF]) << 20) ^ (((uint64_t) SBOX[r2 & 0xF]) << 16)
         ^ (((uint64_t) SBOX[(r3 >> 4) & 0xF]) << 12) ^ (((uint64_t) SBOX[r3 & 0xF]) << 8)
         ^ (uint64_t) r0;
}
    

uint64_t klein_cipher(uint64_t key, uint64_t plain_text) {
    uint64_t sk = key;
    uint64_t text = plain_text;
    uint8_t itr;
    for (itr = 1; itr <= Nr ; itr++) {
        text = Roundkey(text, sk);
        text = substituteNibbles(text);
        text = nib_rotate(text);
        text = colmix(text);
        sk = scheduling_key(sk, itr);
    }
    text = Roundkey(text, sk);
    return text;
}

int main() {
    printf("Provided Key is: %" PRIX64 "\n", KEY);
    printf("Provided Plaintext is:  %" PRIX64 "\n", PLAINTEXT);
    printf("Ciphertext: %" PRIX64 "\n", klein_cipher(KEY, PLAINTEXT));
    return 0;
}
