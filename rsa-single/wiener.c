/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

GEN find_d_cvg(GEN modulus, GEN e) {
  GEN a, c, cf, cvg, m, dd, d = NULL;
  long i, ncvg;
  int found = FALSE;
  pari_sp av = avma;

  /* Encrypts a random message */
  m = gmodulo(randomi(modulus), modulus);
  c = powgi(m, e);

  /* Convergents using PARI functions */
  a = Qdivii(e, modulus);
  cf = gboundcf(a, WIENER_MAX_CVG);
  cvg = contfracpnqn(cf, WIENER_MAX_CVG);
  ncvg = glength(cvg);
  for(i = 1; i <= ncvg; i++) {
    dd = gcoeff(cvg, 2, i);
    /* Private exponent might be in the list of denominators */
    if (gequal(powgi(c, dd), m)) {
      found = TRUE;
      break;
    }
  }

  /* Garbage cleaning */
  if (found) {
    d = gerepilecopy(av, dd);
  }
  else {
    avma = av;
  }

  return d;
}

/*
 * Factorization with the Wiener attack.
 * If the private exponent is recovered, it tries to factor the modulus.
 * Retunrs TRUE if the factors are found,
 * but if d is not NULL, it might contain the private exponent.
 */
int factor_wiener(GEN modulus, GEN e, GEN *d, GEN *p, GEN *q) {
  int found = FALSE;

  /* We find d in the convergents of e/n */
  *d = find_d_cvg(modulus, e);

  if (*d != NULL) {
    pari_printf("D = %Ps\n", *d);
    found = prime_factor_recovery(modulus, e, *d, PRIME_RECOVERY_MAX_ITER, p, q);
  }

  return found;
}
