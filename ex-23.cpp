#include <stdio.h>



int S0[2][4] = { {1, 0, 3, 2}, {3, 2, 1, 0} };

int S1[2][4] = { {0, 2, 1, 3}, {3, 1, 3, 2} };





int expand_permute(int input) {

    int output = 0;

    output |= (input & 0x80) >> 4; // MSB

    output |= (input & 0x40) >> 2;

    output |= (input & 0x20);

    output |= (input & 0x10) << 2;

    output |= (input & 0x10) << 1;

    output |= (input & 0x08) << 1;

    output |= (input & 0x04) << 3;

    output |= (input & 0x02) << 3; // LSB

    return output;

}



int sbox_substitution(int input, int sbox[2][4]) {

    int row = ((input & 0x08) >> 2) | (input & 0x01);

    int col = (input & 0x06) >> 1;

    return sbox[row][col];

}



int permute(int input) {

    int output = 0;

    output |= (input & 0x08) >> 2;

    output |= (input & 0x04) >> 1;

    output |= (input & 0x02) << 1;

    output |= (input & 0x01) << 2;

    return output;

}



int f_function(int input, int key) {

    int expanded_input = expand_permute(input);

    int xored_input = expanded_input ^ key;

    int sbox_input1 = (xored_input & 0xF0) >> 4;

    int sbox_input2 = xored_input & 0x0F;

    int sbox_output1 = sbox_substitution(sbox_input1, S0);

    int sbox_output2 = sbox_substitution(sbox_input2, S1);

    int sbox_output = (sbox_output1 << 2) | sbox_output2;

    return permute(sbox_output);

}



int encrypt(int plaintext, int key, int counter) {

    int encrypted = plaintext ^ counter;

    return f_function(encrypted, key) ^ counter;

}



int decrypt(int ciphertext, int key, int counter) {

    int decrypted = ciphertext ^ counter;

    return f_function(decrypted, key) ^ counter;

}



int main() {

    int plaintext = 0b000000010000001000000100;

    int key = 0b0111111101;

    int counter = 0b00000000;



    printf("Plaintext: %x\n", plaintext);

    int ciphertext = encrypt(plaintext, key, counter);

    printf("Ciphertext: %x\n", ciphertext);



    int decrypted_plaintext = decrypt(ciphertext, key, counter);

    printf("Decrypted Plaintext: %x\n", decrypted_plaintext);

    

    return 0;

}
