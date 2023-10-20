#include "mysha512.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


// MACROS
//
// rotate right 64-bit value
#define ROR64(val, n) ((val >> n) | (val << (64 - n)))

#define S0(a) (ROR64(a,28) ^ ROR64(a,34) ^ ROR64(a,39))
#define S1(a) (ROR64(e,14) ^ ROR64(e,18) ^ ROR64(e,41))

#define sig0(w) (ROR64(w,1) ^ ROR64(w,8) ^ (w >> 7))
#define sig1(w) (ROR64(w,19) ^ ROR64(w,61) ^ (w >> 6))

#define CH(e,f,g) ((e & f) ^ ((~e) & g))
#define MAJ(a,b,c) ((a & b) ^ (a & c) ^ (b & c))

void printData(uint8_t* start, size_t size){
  for(int i = 0; i < size; ++i){
    if(i % 16 == 0){
      printf("\n[%04d]", i);
    }
    printf(" %02x", start[i]);
  }
  printf("\n\n");
}

void printWord64(uint64_t* start, size_t size){
  for(int i = 0; i < size; ++i){
    if(i % 4 == 0){
      printf("\n[%04d]", i);
    }
    printf(" %016llx", start[i]);
  }
  printf("\n\n");
}

void printHashes(Context* c, size_t r){
  printf("\nRound [%04lx]",r);
  for(int i =0; i < 8; ++i){
    printf("%016llx ", c->hash_val[i]);
  }
  printf("\n");
}

// define the round constants
static uint64_t k[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
  0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
  0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
  0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
  0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
  0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
  0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
  };

uint64_t swapEndian64(uint64_t value){

 return (((value & 0x00000000000000FF) << 56u) | \
  ((value & 0x000000000000FF00) << 40u) | \
  ((value & 0x0000000000FF0000) << 24u) | \
  ((value & 0x00000000FF000000) << 8u) | \
  ((value & 0x000000FF00000000) >> 8u) | \
  ((value & 0x0000FF0000000000) >> 24u) | \
  ((value & 0x00FF000000000000) >> 40u) | \
  ((value & 0xFF00000000000000) >> 56u));
}

void sha512Init(Context* sha_context){
  /*
  sha_context->hash_val[0] = swapEndian64(0x6a09e667f3bcc908);
  sha_context->hash_val[1] = swapEndian64(0xbb67ae8584caa73b);
  sha_context->hash_val[2] = swapEndian64(0x3c6ef372fe94f82b);
  sha_context->hash_val[3] = swapEndian64(0xa54ff53a5f1d36f1);
  sha_context->hash_val[4] = swapEndian64(0x510e527fade682d1);
  sha_context->hash_val[5] = swapEndian64(0x9b05688c2b3e6c1f);
  sha_context->hash_val[6] = swapEndian64(0x1f83d9abfb41bd6b);
  sha_context->hash_val[7] = swapEndian64(0x5be0cd19137e2179);
  */
  sha_context->hash_val[0] = 0x6a09e667f3bcc908;
  sha_context->hash_val[1] = 0xbb67ae8584caa73b;
  sha_context->hash_val[2] = 0x3c6ef372fe94f82b;
  sha_context->hash_val[3] = 0xa54ff53a5f1d36f1;
  sha_context->hash_val[4] = 0x510e527fade682d1;
  sha_context->hash_val[5] = 0x9b05688c2b3e6c1f;
  sha_context->hash_val[6] = 0x1f83d9abfb41bd6b;
  sha_context->hash_val[7] = 0x5be0cd19137e2179;

  sha_context->currlen = 0;
  sha_context->length = 0;
}

uint64_t sha512Padding(uint8_t char_num)
{
  // pad the message with bits to make it multiple of 1024
  // IN: length of string
  // OUT: the length of the padding needed to make it multiple of 1024
  
  uint64_t data_bits = char_num * 8;
  data_bits += 129; // add the lenght in 129 bits at end
  uint64_t stream_length = (data_bits/1024) + 1; // bits that need to be added for it to be n*1024

  return stream_length;
}

void sha512Update(uint32_t char_num, char* str, Context* sha_context){
  // find padding
  uint64_t byte_num = sha512Padding(char_num) * 128; // full length of padded msg in bytes
  sha_context->length = byte_num;
  uint8_t* padded = (uint8_t*)malloc(sizeof(uint8_t)*byte_num);
  // create string with padding
  for(int i = 0; i < byte_num; ++i){
    if(i < char_num)
    {
      padded[i] = str[i];
    }
    else if( i >= char_num)
    {
      padded[i] &= 0x00;
    }
  }
  // set bit after last character in msg to 1
  // 0x8 == 0b1000
  memset(&padded[char_num], 0x80, 1);
  char_num *= 8;
  // length of the message (aka number of bits) in big endian
  // assume that no msgs longer than 2^64-1
  uint64_t be_val = swapEndian64((uint64_t)char_num);
  memcpy(&(padded[byte_num - 8]), &be_val, sizeof(uint64_t));


  // print the padded string for debugging
  printf("padded bit string:");
  printData(padded, byte_num);

  //////////////////////////////////////////////////////////
  // process in 1024 chuncks
  while(sha_context->currlen < sha_context->length){
    // load block into message buffer
    for(int i = 0; i < 128; ++i){
      sha_context->message_schedule[i] = padded[sha_context->currlen+i];
      //printf("%x", sha_context->message_schedule[i]);
    }
    sha_context->currlen += 128;
    printf("string copied to sha_context: ");
    printData(sha_context->message_schedule, 128);

    // copy into the w
    uint64_t w[80] = {0};
    for(int i = 0; i < 16; ++i){
      // abuse the cotiguousness of arrays to make 4 8-bit ints into 1 64-bit int
      uint64_t* tmp = &(sha_context->message_schedule[8*i]);
      *tmp = swapEndian64(*tmp);
      //memcpy(&w[i], &tmp, 8);
      w[i] = *tmp;
    }

    // extend w[0..15] to w[16..79]
    for(int i = 16; i < 80; ++i){
      w[i] = w[i-16] + sig0(w[i-15]) + w[i-7] + sig1(w[i-2]);
    } 
    // output for debugging
    printf("data copied to w[0..15]: ");
    printWord64(w, 80);

    ////////////////////////////////////////////////////////
    // compression start
    uint64_t a = sha_context->hash_val[0];
    uint64_t b = sha_context->hash_val[1];
    uint64_t c = sha_context->hash_val[2];
    uint64_t d = sha_context->hash_val[3];
    uint64_t e = sha_context->hash_val[4];
    uint64_t f = sha_context->hash_val[5];
    uint64_t g = sha_context->hash_val[6];
    uint64_t h = sha_context->hash_val[7];

    // compression main loop
    for(int r = 0; r < 80; ++r){
      uint64_t t1 = h + S1(e) + CH(e,f,g) + k[r] + w[r];
      uint64_t t2 = S0(a) + MAJ(a, b, c);


      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    sha_context->hash_val[0] += a;
    sha_context->hash_val[1] += b;
    sha_context->hash_val[2] += c;
    sha_context->hash_val[3] += d;
    sha_context->hash_val[4] += e;
    sha_context->hash_val[5] += f;
    sha_context->hash_val[6] += g;
    sha_context->hash_val[7] += h;

  }

  free(padded);
}

void sha512Digest(Context* sha_context, Digest* digest){
  //put hashes into Digest
  for(int i = 0; i < 8; ++i)
  {
    digest->digest[i] = sha_context->hash_val[i];
  }

}

