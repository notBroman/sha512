#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "mysha512.h"


int main(int argv, char** argc)
{
  Context c;
  Digest d;
  char choices[36] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0'};
  char str[20] = {0};
  char* test1 = {"f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a"};
  char result[129] = {0};

  uint64_t i = 0;
  uint64_t j = 36*36*36;
  uint64_t k = 36*36*36*36;
  uint64_t l = 36*36*36*36*36;

  while(i < 36){
    if(i < 36){
      sprintf(str, "%c",choices[i%36]);
    }
    else if(i < 36*36){
      sprintf(str, "%c%c",choices[(i/36)%(36)],choices[i%36]);
    }
    else if(i < 36*36*36){
      sprintf(str, "%c%c%c",choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
    }
    else if(i < k){
      sprintf(str, "%c%c%c%c",choices[(i/j)%(36)],choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
    }
    else if(i < l){
      sprintf(str, "%c%c%c%c%c",choices[(i/k)%(36)],choices[(i/j)%(36)],choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
    }
    else if(i < LLONG_MAX){
      sprintf(str, "%c%c%c%c%c%c",choices[(i/l)%(36)],choices[(i/k)%(36)],choices[(i/j)%(36)],choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
    }

    sha512Init(&c);
    sha512Update(1, str, &c);
    sha512Digest(&c, &d);


    sprintf(result, "%llx%llx%llx%llx%llx%llx%llx%llx", d.digest[0], d.digest[1], d.digest[2], d.digest[3],d.digest[4],d.digest[5],d.digest[6],d.digest[7]);
    if (memcmp(test1, result, 128) == 0){
      printf("%s", str);
      break;
    }
    ++i;
  }
  return 0;

}
