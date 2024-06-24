#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <ctype.h>



#define ALPHABET_SIZE 26



// English letter frequencies (approximate percentages)

double englishFreq[ALPHABET_SIZE] = {

    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,

    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,

    2.758, 0.978, 2.360, 0.150, 1.974, 0.074

};

// Function to decrypt the ciphertext with a given key

void decrypt(const char *ciphertext, char *plaintext, int key) {

    int i;

    for (i = 0; ciphertext[i] != '\0'; i++) {

        if (isalpha(ciphertext[i])) {

            char base = isupper(ciphertext[i]) ? 'A' : 'a';

            plaintext[i] = (ciphertext[i] - base - key + ALPHABET_SIZE) % ALPHABET_SIZE + base;

        } else {

            plaintext[i] = ciphertext[i];

        }

    }

    plaintext[i] = '\0';

}

// Function to calculate the frequency score of a given plaintext

double calculateScore(const char *plaintext) {

    int i, letterCount[ALPHABET_SIZE] = {0};
    int totalLetters = 0;
    double score = 0.0;

    // Count the frequency of each letter

    for (i = 0; plaintext[i] != '\0'; i++) {

        if (isalpha(plaintext[i])) {

            letterCount[toupper(plaintext[i]) - 'A']++;

        totalLetters++;

        }

    }



    // Calculate the score based on English letter frequencies

    for (i = 0; i < ALPHABET_SIZE; i++) {

        double observedFreq = (double)letterCount[i] / totalLetters * 100;

        score += englishFreq[i] * observedFreq;

    }

    return score;

}



// Function to compare two scores (for sorting)

int compareScores(const void *a, const void *b) {

    double scoreA = *(double*)a;

    double scoreB = *(double*)b;

    return (scoreB > scoreA) - (scoreB < scoreA);

}



// Function to perform frequency analysis attack

void frequencyAttack(const char *ciphertext, int numTopPlaintexts) {

    int key, i;

    char possiblePlaintexts[ALPHABET_SIZE][1000];

    double scores[ALPHABET_SIZE];



    // Decrypt with all possible keys and calculate scores

    for (key = 0; key < ALPHABET_SIZE; key++) {

        decrypt(ciphertext, possiblePlaintexts[key], key);

        scores[key] = calculateScore(possiblePlaintexts[key]);

    }



    // Sort keys based on scores (higher score means more likely)

    int sortedIndices[ALPHABET_SIZE];

    for (i = 0; i < ALPHABET_SIZE; i++) {

        sortedIndices[i] = i;

    }



    for (i = 0; i < ALPHABET_SIZE - 1; i++) {

        for (int j = 0; j < ALPHABET_SIZE - i - 1; j++) {

            if (scores[sortedIndices[j]] < scores[sortedIndices[j + 1]]) {

                int temp = sortedIndices[j];

                sortedIndices[j] = sortedIndices[j + 1];

                sortedIndices[j + 1] = temp;

            }

        }

    }



    // Print the top possible plaintexts

    printf("Top %d possible plaintexts:\n", numTopPlaintexts);

    for (i = 0; i < numTopPlaintexts && i < ALPHABET_SIZE; i++) {

        int keyIndex = sortedIndices[i];

        printf("Key %d: %s\n", keyIndex, possiblePlaintexts[keyIndex]);

    }

}



int main() {

    char ciphertext[] = "ZEBRAS ARE AWESOME";

    int numTopPlaintexts = 10;

    printf("Ciphertext: %s\n", ciphertext);

    frequencyAttack(ciphertext, numTopPlaintexts);

    return 0;

}
