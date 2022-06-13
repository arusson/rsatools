/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

/*
 * Factor modulus if p = p1*m + p0 with m and p1 are known.
 * The integer m can be a power of 2 or any other number.
 * It works if p0 < p^(1/2).
 */
int factor_p_hi(GEN modulus, GEN p1, GEN m, GEN *p, GEN *q) {
  GEN pol, res, B, p1m;
  long nbsol, i;
  int found = FALSE;
  pari_sp av = avma;

  /* Construct pol = x + p1*m and apply Coppersmith */
  p1m = gmul(p1, m);
  B = powuu(2, logint(modulus, gen_2)/2);
  pol = deg1pol(gen_1, p1m, 0);
  res = zncoppersmith(pol, modulus, m, B);

  /* Reconstruct the primes from the small roots */
  nbsol = lg(res) - 1;
  for(i = 1; i <= nbsol; i++) {
    *p = gadd(p1m , gel(res, i));
    if (gdvd(modulus, *p) == 1) {
      *q = gdivexact(modulus, *p);
      found = TRUE;
      break;
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

/*
 * Factor modulus if p = p1*m + p0 with m and p0 are known.
 * The integer m can be a power of 2 or any other number.
 * It works if p1 < p^(1/2)
 */
int factor_p_low(GEN modulus, GEN p0, GEN m, GEN *p, GEN *q) {
  GEN pol, res, X, B;
  long nbsol, i, prime_len;
  int found = FALSE;
  pari_sp av = avma;

  /* Construct pol = x*m + p0 */
  prime_len = (logint(modulus, gen_2) + 1)/2;
  X = gdiv(powuu(2, prime_len), m);
  B = powuu(2, prime_len - 1);
  pol = deg1pol(m, p0, 0);
  res = zncoppersmith(pol, modulus, X, B);

  /* Reconstruc the primes from the small roots */
  nbsol = lg(res) - 1;
  for(i = 1; i <= nbsol; i++) {
    *p = gadd(gmul(gel(res, i), m), p0);
    if (gdvd(modulus, *p) == 1) {
      *q = gdivexact(modulus, *p);
      found = TRUE;
      break;
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
