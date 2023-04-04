int v[100];

void foo (int i, int a) {
  v[i] = a;
}

int main (int a, int b) {

  int result = 3;

  if (a < b) {
    int i;
    for (i=0; i < 3; i++) {
      foo(i, a);
    }
 }

  return result;
}

'''
In this program, if a<b --> v[0] = a , v[1] = a , v[2] = a. Consequently, Angr should indicate that these three memory locations are tainted. Is it possible? How?

'''