
int v = 0;

int foo (int v) {

  return v++;
  
}

int foo1 (int v) {

  return v++;
  
}

int main (int a, int b) {

  if (a == 2) {
      
    return foo(b);
    
  }
  
  else {
      
      return foo1(a);
 }
}

