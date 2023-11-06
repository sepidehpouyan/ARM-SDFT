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