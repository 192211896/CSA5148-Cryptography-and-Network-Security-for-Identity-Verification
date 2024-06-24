#include <stdio.h>

int extended_euclidean(int a, int b, int* x, int* y) {

    if (a == 0) {

        *x = 0;

        *y = 1;

        return b;

    }

    

    int x1, y1;

    int gcd = extended_euclidean(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;

    *y = x1;

    return gcd;

}





int mod_inverse(int a, int m) {

    int x, y;

    int gcd = extended_euclidean(a, m, &x, &y);

    if (gcd != 1) {

        printf("Inverse does not exist\n");

        return -1;

    }

    return (x % m + m) % m;

}



int main() {

    int e = 31;

    int n = 3599;

    int p = 59;

    int q = 61;

    int phi_n = (p - 1) * (q - 1);

     int d = mod_inverse(e, phi_n);

    

    printf("Private key (d): %d\n", d);

    

    return 0;

}
