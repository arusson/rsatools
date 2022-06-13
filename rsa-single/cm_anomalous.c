/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

int factor_cm_anomalous_core(GEN modulus, long disc_i, GEN *p, GEN *q) {
  GEN H, Hmod, g, inv_den, x;
  GEN r, A, B, tmp;
  GEN x0, res_x, res_z, res;
  GEN disc;
  long xn;
  int n = 0, found = FALSE;
  pari_sp av = avma, start_loop;

  disc = stoi(disc_i);

  /* 
   * Step 1:
   * We construct the ring R = (Z/nZ)[x]/H_j(x)
   */
  H = polclass(disc, 0, -1);  /* Hilbert polynomial */
  Hmod = gmodulo(H, modulus); /* Polynomial in Z/nZ ring */
  xn = varn(Hmod);
  x = pol_x(xn);  
  g = gsubsg(1728, x);
  inv_den = ginvmod(g, Hmod); /* 1/(1728 - x) mod H_j(x) */

  while (n < CM_ANOMALOUS_MAX_ATTEMPTS) {
    start_loop = avma;
    if (verb) {
      fprintf(stderr, "    Run %d out of %d\n", n+1, CM_ANOMALOUS_MAX_ATTEMPTS);
    }

    /* 
     * Step 2:
     * We construct the elliptic curve y^2 = x^3 + A*x + B over the ring R
     *     A = (3xr^2)/(1728 - x) over R
     *     B = (2xr^3)/(1728 - x) over R
     */
    r = randomi(modulus);
    tmp = gsqr(r);
    A = gmodulo(gmul(gmul(gmulgs(tmp,3), x), inv_den), Hmod);
    tmp = gmul(tmp, r);
    B = gmodulo(gmul(gmul(gmulgs(tmp,2), x), inv_den), Hmod); 
    
    /* 
     * Step 3:
     * We construct the point P = (x0, .) a point on the curve
     */
    x0 = randomi(modulus);

    /*
     * Step 4:
     * scalar multiplication with Montgomery ladder algorithm
     */
    ladder(modulus, x0, A, B, &res_x, &res_z);

    /* 
     * Step 5:
     * We find the prime factor with the Z-coordinate:
     * - We lift the coordinate Z to ZZ[X]
     * - We compute the resultant with Hilbert polynomial to get an integer
     * - Finally, gcd to get (hopefully) the prime factor
     */
    res = gmod(ZX_resultant(H, lift(lift(res_z))), modulus);
    *p = gcdii(res, modulus);
    /* If non-trivial gcd, we have the prime factor */
    if (gcmp(*p, gen_1) == 1 && gcmp(*p, modulus) == -1) {
      *q = gdivexact(modulus, *p);
      found = TRUE;
      break;
    }
    avma = start_loop;
    n++;
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

/* Factor modulus, trying discriminants D with -max_disc < D <= -3 */
int factor_cm_anomalous(GEN modulus, GEN *p, GEN *q, int max_disc) {
  int found = FALSE;
  int disc_i = -3;

  if (verb) {
    fprintf(stderr, "    Discriminants between -3 and -%d will be tested\n", max_disc);
  }
  while (!found && disc_i > -max_disc) {
    if (verb) {
      fprintf(stderr, "    Testing discriminant %d\n", disc_i);
    }
    found = factor_cm_anomalous_core(modulus, disc_i, p, q);
    disc_i -= 4;
  }
  
  return found;
}
