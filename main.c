#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "mysha512.h"


int main(int argv, char** argc)
{
  Context c;
  Digest d;
  char choices[36] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0'};
  char str[20] = {0};
  char* test1 = {"f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a"};
  char* test2 = {"e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24"};
  char* test3 = {"4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80"};
  char* test4 = {"afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b"};
  char result[129] = {0};
  char** cases[4] = {&test1, &test2, &test3, &test4};

  uint64_t i = 0;
  uint64_t j = 36*36*36;
  uint64_t k = 36*36*36*36;
  uint64_t l = 36*36*36*36*36;

  int length = 1;

  for(int case_num = 0; case_num < 4; ++case_num){
    clock_t begin = clock();
    i = 0;
    while(length < 7){
      switch(length){
        case 1:
          sprintf(str, "%c",choices[i%36]);
          break;

        case 2:
          sprintf(str, "%c%c",choices[(i/36)%(36)],choices[i%36]);
          break;

        case 3:
          sprintf(str, "%c%c%c",choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
          break;

        case 4:
          sprintf(str, "%c%c%c%c",choices[(i/j)%(36)],choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
          break;
  
        case 5:
          sprintf(str, "%c%c%c%c%c",choices[(i/k)%(36)],choices[(i/j)%(36)],choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
          break;

        case 6:
          sprintf(str, "%c%c%c%c%c%c",choices[(i/l)%(36)],choices[(i/k)%(36)],choices[(i/j)%(36)],choices[(i/(36*36))%(36)],choices[(i/36)%(36)],choices[i%36]);
          break;
        
        default:
          printf("DEFAULT STATE WHY?");

      }

      sha512Init(&c);
      sha512Update(length, str, &c);
      sha512Digest(&c, &d);


      sprintf(result, "%llx%llx%llx%llx%llx%llx%llx%llx", d.digest[0], d.digest[1], d.digest[2], d.digest[3],d.digest[4],d.digest[5],d.digest[6],d.digest[7]);
      if (memcmp(*cases[case_num], result, 128) == 0){
        clock_t end = clock();
        double time = (double)(end - begin)/CLOCKS_PER_SEC;
        printf("plaintext: %s\ntime: %lf \n\n", str, time);
        break;
      }

      if(i == pow(36,length)){
        ++length;
        i=0;
      }
      else{
        ++i;
      }
    }
  }
  return 0;

}
