#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void toUpperCase(char* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        str[i] = toupper(str[i]);
    }
}

void generateKey(const char* str, const char* key, char* newKey) {
    int strLen = strlen(str);
    int keyLen = strlen(key);

    for (int i = 0, j = 0; i < strLen; ++i, ++j) {
        if (j == keyLen)
            j = 0;
        newKey[i] = key[j];
    }
    newKey[strLen] = '\0';
}

void encrypt(const char* str, const char* key, char* encryptedText) {
    int strLen = strlen(str);

    for (int i = 0; i < strLen; ++i) {
        if (isalpha(str[i])) {
            char offset = isupper(str[i]) ? 'A' : 'a';
            encryptedText[i] = ((str[i] + key[i] - 2 * offset) % 26) + offset;
        } else {
            encryptedText[i] = str[i];
        }
    }
    encryptedText[strLen] = '\0';
}

void decrypt(const char* encryptedText, const char* key, char* decryptedText) {
    int strLen = strlen(encryptedText);

    for (int i = 0; i < strLen; ++i) {
        if (isalpha(encryptedText[i])) {
            char offset = isupper(encryptedText[i]) ? 'A' : 'a';
            decryptedText[i] = (((encryptedText[i] - key[i]) + 26) % 26) + offset;
        } else {
            decryptedText[i] = encryptedText[i];
        }
    }
    decryptedText[strLen] = '\0';
}

int main() {
    char str[100], key[100], newKey[100], encryptedText[100], decryptedText[100];

    printf("Enter the plaintext: ");
    fgets(str, sizeof(str), stdin);
    str[strcspn(str, "\n")] = '\0';  // Remove the newline character

    printf("Enter the key: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';  // Remove the newline character

    // Convert to uppercase
    toUpperCase(str);
    toUpperCase(key);

    // Generate the new key
    generateKey(str, key, newKey);

    // Encrypt the string
    encrypt(str, newKey, encryptedText);
    printf("Encrypted Text: %s\n", encryptedText);

    // Decrypt the string
    decrypt(encryptedText, newKey, decryptedText);
    printf("Decrypted Text: %s\n", decryptedText);

    return 0;
}

