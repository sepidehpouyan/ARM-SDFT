
int v = 0;
int c = 2;

int foo ( int v ) {

  return v++;
  
}

int main (int a, int b) {

  if (a < 2) {
      
    return foo(b);
    
  }
  
  return 0;
}

