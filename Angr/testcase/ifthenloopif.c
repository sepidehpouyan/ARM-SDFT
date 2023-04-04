static int v = 0;

int foo (int i) {

  v += i;
 return v;
 
 }

int main (int a, int b) {

  int result = 3;

  if (a < b) {
      
    int i;

    for (i=0; i<3; i++) {
        
      if ((b + foo(1)) < a) {
          
        (void) foo(b);
      }
    }
  }

  return result;
}