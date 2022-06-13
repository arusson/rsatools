/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

int factor_close_primes(GEN modulus, GEN *p, GEN *q, const int max) {
  int i, found = FALSE;
  pari_sp av = avma;

  if (verb) {
    fprintf(stderr, "    x = floor(sqrt(n)) and checks if (x + k)^2 - n is a square with 0 <= k < %d\n"
                    "    Maximal value for k can be increased with the `--fermat-bound` option\n", max);
  }

  *p = sqrti(modulus);
  for(i = 0; i < max; i++) {
    *q = gsqr(*p);
    *q = gsub(*q, modulus);
    if (Z_issquareall(*q, q)) {
      *p = gadd(*p, *q);
      *q = gmul(*q, gen_2);
      *q = gsub(*p, *q);
      found = TRUE;
      break;
    }
    *p = gadd(*p, gen_1);
    
    if (gc_needed(av, 1)) {
      gerepileall(av, 2, p, q);
    }
  }

  /* Garbage cleaning */
  if (found) {
    gerepileall(av, 2, p, q);
  }
  else {
    avma = av;
  }
  
  return found;
}