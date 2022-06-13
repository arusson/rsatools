/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

int factor_p_plus_minus_one(GEN modulus, GEN *p, GEN *q, GEN maxprime, long logbound) {
  int found = FALSE, n = 0, i;
  long len, bit, e;
  GEN x, x0, x1, pp, exponent;
  pari_sp av = avma, start_loop;
  forprime_t T;

  if (verb) {
    pari_fprintf(stderr, "    This attack is expected to work if p-1 (or p+1)\n"
                         "    has prime power factors less than 2^%d\n"
                         "    with primes less than %Ps\n", logbound, maxprime);
  }

  /* 
   * We compute the x-coordinate of [M]P with a smooth M,
   * and P belongs either to the circle of equation x^2 + y^2 = 4
   * or to the hyperbola of equation x^2 - y^2 = 4.
   * One curve has p-1 points, the other has p+1 points.
   */
  while (!found && n < P_PM_1_MAX_ATTEMPTS) {
    if (verb) {
      fprintf(stderr, "    Run %d out of %d\n", n+1, P_PM_1_MAX_ATTEMPTS);
    }
    x0 = gmodulo(randomi(modulus), modulus);
    forprime_init(&T, gen_2, maxprime);
    start_loop = avma;
    while ((pp = forprime_next(&T))) {
      if (pp == NULL) { break; }
      e = logbound/logint(pp, gen_2);
      exponent = powiu(pp, e);
      
      /* Ladder exponentiation */
      len = logint(exponent, gen_2) + 1;
      x = gcopy(x0);
      x1 = gsub(gsqr(x0), gen_2);
      for (i = len - 2; i >= 0; i--) {
        bit = bittest(exponent, i);
        if (bit == 1) {
          x0 = gsub(gmul(x0, x1), x);
          x1 = gsubgs(gsqr(x1), 2);
        }
        else {
          x1 = gsub(gmul(x0, x1), x);
          x0 = gsubgs(gsqr(x0), 2);
        }
      }

      /* 
       * If non-trivial gcd, we have the prime factor.
       * Otherwise we continue until the bound is reached.
       */
      *p = gcdii(lift(gsub(x0, gen_2)), modulus);
      if (!gequal1(*p) && !gequal(*p, modulus)) {
        *q = gdivexact(modulus, *p);
        found = TRUE;
        break;
      }

      /* Garbage cleaning if needed */
      if (gc_needed(start_loop, 1)) {
        x0 = gerepilecopy(start_loop, x0);
      }

    }
    n++;
    /* Garbage cleaning */
    avma = av;
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