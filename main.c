#include <stdint.h>
#include <stdio.h>
#include "mysha512.h"


int main(int argv, char** argc)
{
  Context c;

  sha512Init(&c);
  char* str = {"m"};

  sha512Update(1, str, &c);

  printf("Hello world\n");

}
