/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

/*
 * Compute square root of a mod 2^u.
 * Only if u >= 3 and a mod 8 = 1.
 */
GEN sqrt_mod2(GEN a, long u) {
  GEN pow2, root1, root2, root3, root4, roots = NULL;
  long i;
  pari_sp av = avma;

  /* Solutions only if a mod 8 = 1 */
  if (Mod8(a) == 1) {
    root1 = gen_1;
    pow2 = gen_2;
    for(i = 3; i < u; i++) {
      pow2 = shifti(pow2, 1);
      if (bittest(gsub(gsqr(root1), a), i)) {
        root1 = gadd(root1, pow2);
      }
    }
    pow2 = shifti(pow2, 1);
    root2 = gneg(root1);
    root3 = gadd(root1, pow2);
    root4 = gadd(root2, pow2);
    pow2 = shifti(pow2, 1);
    root2 = gmod(root2, pow2);
    root3 = gmod(root3, pow2);
    root4 = gmod(root4, pow2);
    roots = mkvecn(4, root1, root2, root3, root4);
  }

  /* Garbage cleaning */
  if (roots != NULL) {
    roots = gerepilecopy(av, roots);
  }
  else {
    avma = av;
  }
  return roots;
}