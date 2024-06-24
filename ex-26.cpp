#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function to compute gcd
int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Function to compute (base^exponent) % modulus using modular exponentiation
int mod_exp(int base, int exponent, int modulus) {
    int result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

// Function to compute modular multiplicative inverse of a under modulus m
int mod_inverse(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1)
        return 0;

    // Apply extended Euclid Algorithm
    while (a > 1) {
        // q is quotient
        q = a / m;
        t = m;

        // m is remainder now, process same as euclid's algo
        m = a % m, a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < 0)
        x1 += m0;

    return x1;
}

// Function to generate RSA key pair
void generate_keys(int *n, int *e, int *d, int p, int q) {
    *n = p * q;
    int phi = (p - 1) * (q - 1);

    // Choose e such that 1 < e < phi and gcd(e, phi) = 1
    *e = 3;
    while (gcd(*e, phi) != 1) {
        (*e)++;
    }

    // Compute d to satisfy d*e = 1 (mod phi)
    *d = mod_inverse(*e, phi);
}

// Function to encrypt a message
int encrypt(int msg, int e, int n) {
    return mod_exp(msg, e, n);
}

// Function to decrypt a message
int decrypt(int cipher, int d, int n) {
    return mod_exp(cipher, d, n);
}

int main() {
    // Select two prime numbers
    int p = 61, q = 53;
    int n, e, d;

    // Generate public and private keys
    generate_keys(&n, &e, &d, p, q);

    printf("Public Key: (n = %d, e = %d)\n", n, e);
    printf("Private Key: (n = %d, d = %d)\n", n, d);

    // Message to be encrypted
    int msg = 42;
    printf("Original Message: %d\n", msg);

    // Encrypt the message
    int cipher = encrypt(msg, e, n);
    printf("Encrypted Message: %d\n", cipher);

    // Decrypt the message
    int decrypted_msg = decrypt(cipher, d, n);
    printf("Decrypted Message: %d\n", decrypted_msg);

    return 0;
}
