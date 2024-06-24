
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Function to find modulo
int mod(int a, int b) {
    int result = a % b;
    if (result < 0) {
        result += b;
    }
    return result;
}

// Function to encrypt the message using Hill cipher
void hillCipherEncrypt(char *message, int key[2][2], char *encryptedMessage) {
    int i, j;
    int messageLength = strlen(message);

    // Pad message length to even if necessary
    if (messageLength % 2 != 0) {
        message[messageLength] = 'x';
        message[messageLength + 1] = '\0';
        messageLength++;
    }

    for (i = 0; i < messageLength; i += 2) {
        // Convert characters to numbers
        int firstChar = toupper(message[i]) - 'A';
        int secondChar = toupper(message[i + 1]) - 'A';

        // Apply the key matrix to the character pair
        int firstEncryptedChar = mod((key[0][0] * firstChar + key[0][1] * secondChar), 26);
        int secondEncryptedChar = mod((key[1][0] * firstChar + key[1][1] * secondChar), 26);

        // Convert numbers back to characters
        encryptedMessage[i] = firstEncryptedChar + 'A';
        encryptedMessage[i + 1] = secondEncryptedChar + 'A';
    }
    encryptedMessage[messageLength] = '\0'; // Null terminate the string
}

int main() {
    char message[] = "meet me at the usual place at ten rather than eight oclock";
    char cleanMessage[100];
    char encryptedMessage[100];
    int key[2][2] = {{9, 4}, {5, 7}};
    
    // Remove spaces from the message and convert to uppercase
    int i, j = 0;
    for (i = 0; message[i] != '\0'; i++) {
        if (message[i] != ' ') {
            cleanMessage[j++] = toupper(message[i]);
        }
    }
    cleanMessage[j] = '\0';

    // Encrypt the message
    hillCipherEncrypt(cleanMessage, key, encryptedMessage);

    printf("Original Message: %s\n", message);
    printf("Clean Message: %s\n", cleanMessage);
    printf("Encrypted Message: %s\n", encryptedMessage);

    return 0;
}

