/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include <pari/pari.h>

const char *HEX = "0123456789abcdef";

GEN bytes_to_hex(const unsigned char buf[8]) {
  int i;
  char seedhex[19];

  seedhex[0] = '0';
  seedhex[1] = 'x';
  for(i = 0; i < 8; i++) {
    seedhex[2*i + 2] = HEX[(buf[i] >> 4)];
    seedhex[2*i + 3] = HEX[buf[i] & 15];
  }
  seedhex[18] = '\0';

  return gp_read_str(seedhex);
}

GEN getseed() {
  FILE *fp;
  GEN seed = gen_1;
  unsigned char bytes[8];

  fp = fopen("/dev/urandom", "rb");
  if (fp != NULL && fread(bytes, 8, 1, fp)) {
    seed = bytes_to_hex(bytes);
    fclose(fp);
  }
  
  return seed;
}