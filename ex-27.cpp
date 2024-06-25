#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to perform modular exponentiation
unsigned long long mod_exp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Function to find the plaintext corresponding to a given ciphertext using precomputed values
int find_plaintext(unsigned long long ciphertext, unsigned long long* precomputed, int size) {
    for (int i = 0; i < size; i++) {
        if (precomputed[i] == ciphertext) {
            return i;
        }
    }
    return -1; // Not found
}

int main() {
    unsigned long long e = 65537; // Example public exponent
    unsigned long long n = 3233;  // Example modulus (small for demonstration purposes)

    // Precompute the ciphertexts for all plaintext values (0 to 25)
    unsigned long long precomputed[26];
    for (int i = 0; i < 26; i++) {
        precomputed[i] = mod_exp(i, e, n);
        printf("Plaintext %d -> Ciphertext %llu\n", i, precomputed[i]);
    }

    // Example ciphertexts to decrypt (these would be intercepted ciphertexts in a real attack)
    unsigned long long ciphertexts[] = {2201, 1951, 3060, 11}; // Example encrypted values for demonstration
    int num_ciphertexts = sizeof(ciphertexts) / sizeof(ciphertexts[0]);

    // Decrypt the ciphertexts
    printf("Decrypted message: ");
    for (int i = 0; i < num_ciphertexts; i++) {
        int plaintext = find_plaintext(ciphertexts[i], precomputed, 26);
        if (plaintext != -1) {
            printf("%c", 'A' + plaintext);
        } else {
            printf("?");
        }
    }
    printf("\n");

    return 0;
}

