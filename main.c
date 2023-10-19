#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "mysha512.h"


int main(int argv, char** argc)
{
  Context c;
  Digest d;
  char* str = {"abc"};
  char* test = {"f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a"};

  sha512Init(&c);
  sha512Update(3, str, &c);
  sha512Digest(&c, &d);


  printf("Hello, cruel world\n");

  for(int i = 0; i < 8; ++i){
    printf("%llx", d.digest[i]);
  }
  printf("\n");

  return 0;

}
