/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

int factor_small_modulus(GEN modulus, GEN *p, GEN *q) {
  int found = FALSE;
  GEN res;
  res = Z_factor(modulus);
  /* We expect two primes */
  if (nbrows(res) == 2) {
    *p = gcoeff(res,1,1);
    *q = gcoeff(res,2,1);
    found = TRUE;
  }  
  return found;
}

int factor_square_modulus(GEN modulus, GEN *p, GEN *q) {
  int found = FALSE;
  found = Z_issquareall(modulus, p);
  if (found) {
    *q = gcopy(*p);
  }
  return found;
}