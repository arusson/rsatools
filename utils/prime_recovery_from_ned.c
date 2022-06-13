/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

/*
 * Method from Appendic C.1 of NIST.SP.800-56Br2
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
 */
int prime_factor_recovery(GEN modulus, GEN e, GEN d, const int n_iter, GEN *p, GEN *q) {
  GEN m, r, g, x, y, nm1;
  long t, i, j;
  int found = FALSE;
  pari_sp av = avma, start_loop;

  nm1 = gsub(modulus, gen_1);

  m = gsub(gmul(e, d), gen_1);
  if (mpodd(m)) {
    goto end;
  }

  t = Z_pvalrem(m, gen_2, &r);

  start_loop = avma;
  for(i = 0; i < n_iter; i++) {
    g = gmodulo(randomi(modulus), modulus);
    y = powgi(g, r);
    if (gequal1(y) || gequal(y, nm1)) {
      continue;
    }
    for(j = 1; j < t; j++) {
      x = gsqr(y);
      if (!gequal1(x)) {
        if (gequal(x, nm1)) {
          continue;
        }
      }
      else {
        found = TRUE;
        goto end;
      }
      y = x;
    }
    x = gsqr(y);
    if (gequal1(x)) {
      found = TRUE;
      break;
    }

    /* Garbage cleaning */
    avma = start_loop;
  }

end:
  if (found) {
    *p = gcdii(lift(gsub(y, gen_1)), modulus);
    if (!gequal(*p, gen_1) && !gequal(*p, modulus)) {
      *q = gdivexact(modulus, *p);
    }
    else {
      found = FALSE;
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
