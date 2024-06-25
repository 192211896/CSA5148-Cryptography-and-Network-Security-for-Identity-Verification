#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define STATE_SIZE 25 // 5x5 matrix
#define LANE_SIZE 64  // Each lane is 64 bits

// Initialize the state matrix
void initialize_state(unsigned long long state[STATE_SIZE]) {
    for (int i = 0; i < STATE_SIZE; i++) {
        state[i] = 0;
    }
}

// Check if all lanes in the capacity are nonzero
int all_capacity_lanes_nonzero(unsigned long long state[], int capacity_lanes[]) {
    for (int i = 0; i < STATE_SIZE; i++) {
        if (capacity_lanes[i] && state[i] == 0) {
            return 0;
        }
    }
    return 1;
}

int main() {
    unsigned long long state[STATE_SIZE];
    int capacity_bits, rate_bits;

    // User input for capacity and rate
    printf("Enter capacity in bits (multiple of 64): ");
    scanf("%d", &capacity_bits);
    printf("Enter rate in bits: ");
    scanf("%d", &rate_bits);

    if (capacity_bits % LANE_SIZE != 0) {
        printf("Capacity must be a multiple of 64 bits.\n");
        return 1;
    }

    int capacity_lanes[STATE_SIZE] = {0};

    // Mark the capacity lanes (assuming each lane is 64 bits)
    for (int i = 0; i < capacity_bits / LANE_SIZE; i++) {
        capacity_lanes[i] = 1;
    }

    // Initialize state
    initialize_state(state);

    srand(time(NULL));
    int block_count = 0;

    // Loop until all capacity lanes have at least one nonzero bit
    while (!all_capacity_lanes_nonzero(state, capacity_lanes)) {
        block_count++;

        // Simulate absorbing a block
        for (int i = 0; i < STATE_SIZE; i++) {
            if (rand() % 2 == 0) {
                state[i] ^= (unsigned long long)rand() << 32 | rand();
            }
        }
    }

    printf("Number of blocks absorbed until all capacity lanes are nonzero: %d\n", block_count);

    return 0;
}

