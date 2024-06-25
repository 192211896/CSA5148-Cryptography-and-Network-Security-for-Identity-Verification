#include <stdio.h>
#include <stdlib.h>

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

int main() {
    unsigned long long q, a, x_A, x_B;

    // User input for prime modulus q and base a
    printf("Enter a prime modulus (q): ");
    scanf("%llu", &q);
    printf("Enter a base (a): ");
    scanf("%llu", &a);

    // User input for Alice's secret number
    printf("Alice, enter your secret number (x_A): ");
    scanf("%llu", &x_A);

    // User input for Bob's secret number
    printf("Bob, enter your secret number (x_B): ");
    scanf("%llu", &x_B);

    // Alice computes A = a^x_A % q and sends it to Bob
    unsigned long long A = mod_exp(a, x_A, q);
    printf("Alice sends: %llu\n", A);

    // Bob computes B = a^x_B % q and sends it to Alice
    unsigned long long B = mod_exp(a, x_B, q);
    printf("Bob sends: %llu\n", B);

    // Both compute the shared key
    unsigned long long K_A = mod_exp(B, x_A, q);
    unsigned long long K_B = mod_exp(A, x_B, q);

    printf("Alice's computed key: %llu\n", K_A);
    printf("Bob's computed key: %llu\n", K_B);

    if (K_A == K_B) {
        printf("Shared secret key successfully established: %llu\n", K_A);
    } else {
        printf("Error in key exchange.\n");
    }

    return 0;
}

