#include <stdio.h>
#include <stdlib.h>

int main (int a, int b) {
    int n = 3;
    int i, *ptr;
    ptr = (int*) malloc(n * sizeof(int));
    if (ptr == NULL) {
        exit(0);
    }
    
    for (i = 0; i < n; ++i) {
        *(ptr + i) = a;
    }
    
    return 0;
}