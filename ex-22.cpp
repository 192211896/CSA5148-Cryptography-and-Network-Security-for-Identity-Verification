#include <stdio.h>



void encrypt_sdes_cbc(char *plaintext, char *key, char *iv, int length);

void decrypt_sdes_cbc(char *ciphertext, char *key, char *iv, int length);



void sdes_encrypt(char *block, char *key);

void sdes_decrypt(char *block, char *key);



int main() {

    char plaintext[] = "0000000100100011";  

    char key[] = "0111111101";               

    char iv[] = "10101010";              



    int length = 16;  

    

    encrypt_sdes_cbc(plaintext, key, iv, length);

    

   

    decrypt_sdes_cbc(plaintext, key, iv, length);



    return 0;

}





void sdes_encrypt(char *block, char *key) {

   

}





void sdes_decrypt(char *block, char *key) {

    

}





void encrypt_sdes_cbc(char *plaintext, char *key, char *iv, int length) {

    printf("\nS-DES CBC Encryption:\n");



    

    for (int i = 0; i < length; i += 8) {

        for (int j = 0; j < 8; j++) {

            plaintext[i + j] = plaintext[i + j] ^ iv[j]; 

        }

        sdes_encrypt(plaintext + i, key);

        

        for (int j = 0; j < 8; j++) {

            iv[j] = plaintext[i + j];

        }

    }



    printf("Ciphertext: %s\n", plaintext);

}





void decrypt_sdes_cbc(char *ciphertext, char *key, char *iv, int length) {

    printf("\nS-DES CBC Decryption:\n");



    char prev_ciphertext[9];  



    

    for (int i = 0; i < length; i += 8) {

        for (int j = 0; j < 8; j++) {

            prev_ciphertext[j] = ciphertext[i + j]; 

        }

        sdes_decrypt(ciphertext + i, key);

        for (int j = 0; j < 8; j++) {

            ciphertext[i + j] = ciphertext[i + j] ^ iv[j]; 

        }

       

        for (int j = 0; j < 8; j++) {

            iv[j] = prev_ciphertext[j];

        }

    }

    printf("Decrypted Text: %s\n",ciphertext);

}
