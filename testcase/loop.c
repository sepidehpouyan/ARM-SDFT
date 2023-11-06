static int v = 42;
static int w = 777;

int main(int a, int b){
  int result = 1;
  int i = 0;
  b = 5;
  while (i < b)
  {
    int t = (a & i);

    result *= (t == 0x01) ? v++ : w++;
    i++;
  }
  return result;
}
