#ifndef _MYSHA512_H
#define _MYSHA512_H

/*
*  An implementation of SHA512
*
*  Application of CFB
*/

#include <stdint.h>

typedef struct{
  uint64_t length;
  uint64_t hash_val[8];
  uint64_t currlen;
  uint8_t message_schedule[128];
  uint8_t round;
} Context;

typedef struct{
  char* string;
  uint64_t length;
  
} Data;

void sha512Init(Context* sha_context);
void sha512Compress(Context* sha_context);
void sha512Round(char* block_data, Context* sha_context);
void sha512Update(uint32_t char_num, char* str, Context* sha_context); //given a string and the length of the string
void sha512Digest();

#endif
