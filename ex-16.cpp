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



// Function to count the frequency of each letter in the ciphertext

void calculateFrequencies(const char *text, int *frequencies) {

    for (int i = 0; i < ALPHABET_SIZE; i++) {

        frequencies[i] = 0;

    }

    

    for (int i = 0; text[i] != '\0'; i++) {

        if (isalpha(text[i])) {

            frequencies[toupper(text[i]) - 'A']++;

        }

    }

}



// Function to create an initial substitution map based on frequency analysis

void createInitialMap(int *cipherFreq, char *substitutionMap) {

    int i, j;

    int sortedIndices[ALPHABET_SIZE];

    

    // Create an array of indices sorted by frequency in descending order

    for (i = 0; i < ALPHABET_SIZE; i++) {

        sortedIndices[i] = i;

    }

    

    for (i = 0; i < ALPHABET_SIZE - 1; i++) {

        for (j = 0; j < ALPHABET_SIZE - i - 1; j++) {

            if (cipherFreq[sortedIndices[j]] < cipherFreq[sortedIndices[j + 1]]) {

                int temp = sortedIndices[j];

                sortedIndices[j] = sortedIndices[j + 1];

                sortedIndices[j + 1] = temp;

            }

        }

    }

    

    // Map the most frequent letters in the ciphertext to the most frequent letters in English

    for (i = 0; i < ALPHABET_SIZE; i++) {

        substitutionMap[sortedIndices[i]] = 'A' + i;

    }

}



// Function to decrypt the ciphertext using the substitution map

void decrypt(const char *ciphertext, char *plaintext, const char *substitutionMap) {

    for (int i = 0; ciphertext[i] != '\0'; i++) {

        if (isalpha(ciphertext[i])) {

            char base = isupper(ciphertext[i]) ? 'A' : 'a';

            int index = toupper(ciphertext[i]) - 'A';

            plaintext[i] = substitutionMap[index] - 'A' + base;

        } else {

            plaintext[i] = ciphertext[i];

        }

    }

    plaintext[strlen(ciphertext)] = '\0';

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

    int i;

    int cipherFreq[ALPHABET_SIZE];

    char substitutionMap[ALPHABET_SIZE];

    char possiblePlaintexts[ALPHABET_SIZE][1000];

    double scores[ALPHABET_SIZE];



    // Calculate letter frequencies in the ciphertext

    calculateFrequencies(ciphertext, cipherFreq);



    // Create an initial substitution map based on frequency analysis

    createInitialMap(cipherFreq, substitutionMap);



    // Decrypt with all possible single letter shifts and calculate scores

    for (i = 0; i < ALPHABET_SIZE; i++) {

        decrypt(ciphertext, possiblePlaintexts[i], substitutionMap);

        scores[i] = calculateScore(possiblePlaintexts[i]);

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

        printf("Plaintext %d: %s\n", i + 1, possiblePlaintexts[keyIndex]);

    }

}



int main() {

    char ciphertext[] = "YMNX NX F YT NSL";

    int numTopPlaintexts = 10;



    printf("Ciphertext: %s\n", ciphertext);

    frequencyAttack(ciphertext, numTopPlaintexts);



    return 0;

}
