/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

/* 
 * Factorization of n = p*q
 * if (p - q) mod 2^l = 0 with l > log2(n)/4
 */
int factor_shared_lsb(GEN modulus, GEN *p, GEN *q) {
  GEN roots, m;
  long i, u;
  int found = FALSE;
  pari_sp av = avma;

  roots = cgetg(4, t_VEC);

  /* u = ceil(log2(n)/2) */
  u = (logint(modulus, gen_2) + 2) >> 1;
  roots = sqrt_mod2(modulus, u);
  if (roots != NULL) {
    for(i = 1; i <= 4; i++) {
      m = gsqr(gel(roots, i));
      m = gsub(m, modulus);
      m = shifti(m, -u);
      if (Z_issquareall(m, &m)) {
        m = shifti(m, u >> 1);
        *p = gsub(gel(roots, i), m);
        *q = gadd(gel(roots, i), m);
        found = TRUE;
        break;
      }
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
