#include <stdio.h>

#include <stdlib.h>



#define BLOCK_SIZE 16



// Function to encrypt a single block in ECB mode

void ecb_encrypt_block(unsigned char *plaintext, unsigned char *key) {

    // Perform encryption (dummy operation for demonstration)

    printf("Encrypting plaintext block: ");

    for (int i = 0; i < BLOCK_SIZE; i++) {

        // Dummy encryption: XOR plaintext with key

        plaintext[i] ^= key[i];

        printf("%02x ", plaintext[i]);

    }

    printf("\n");

}



// Function to decrypt a single block in ECB mode

void ecb_decrypt_block(unsigned char *ciphertext, unsigned char *key) {

    // Perform decryption (dummy operation for demonstration)

    printf("Decrypting ciphertext block: ");

    for (int i = 0; i < BLOCK_SIZE; i++) {

        // Dummy decryption: XOR ciphertext with key

        ciphertext[i] ^= key[i];

        printf("%02x ", ciphertext[i]);

    }

    printf("\n");

}



int main() {

    unsigned char plaintext[3][BLOCK_SIZE] = {

        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},

        {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},

        {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30}

    };

    unsigned char key[BLOCK_SIZE] = {0x5A, 0x2B, 0xC3, 0x7D, 0x1F, 0x8E, 0x9A, 0x34, 0x52, 0x76, 0xAB, 0xCD, 0xEF, 0x00, 0x88, 0x99};



    // Encrypt each plaintext block in ECB mode

    for (int i = 0; i < 3; i++) {

        ecb_encrypt_block(plaintext[i], key);

    }



    // Decrypt each ciphertext block in ECB mode

    printf("\n");

    for (int i = 0; i < 3; i++) {

        ecb_decrypt_block(plaintext[i], key);

    }

    

    return 0;

}
