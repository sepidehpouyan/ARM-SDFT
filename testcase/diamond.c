int main (int a, int b) {
  int result;
  int c = 10;
  /* A series of secret-dependent branches */
  if (a == b) {
    result = 0;
  }
  else if (a < b) {
    result = 3;
  }
  else {
    result = 7;
  }
  /* A secret-independent branch */
  if (b == c) {
    //result *= 2; // times two generates really weird assembly...
    result *= 4;
  }
  return result;
}
