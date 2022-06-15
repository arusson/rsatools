/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include "rsa.h"

/* 
 * Detect the value k in the equation
 *   e*d = 1 + k*phi(n).
 * If n mod 4 = 3, do not call this function.
 * It works only if modulus mod 4 = 1, meaning that p and q
 * share more than 2 of their least significant bits.
 */
void k_detect(GEN modulus, GEN e, GEN d0, long u, long treshold) {
  long elong, k, tk, kk, gamma, t, i, ctr = 0, k_best, gamma_best;
  GEN kinv, inv2, a, b, bb, n1, ed1, pow2u, pow2tk1, pow2v, roots;
  pari_sp av = avma, start_loop;

  /* 
   * A low treshold for the minimal number of shared lsb
   * would give too many results. Consider at least 8.
   */
  if (treshold < 4) {
    treshold = 4;
  }

  elong = itos(e);
  pow2u = shifti(gen_1, u);
  ed1 = gmod(gsub(gmul(e, d0), gen_1), pow2u);
  inv2 = ginvmod(gen_2, e);
  n1 = gadd(modulus, gen_1);
  
  k_best = 1;
  gamma_best = 1;

  start_loop = avma;
  for(k = 1; k < elong; k++) {
    /* Garbage cleaning */
    avma = start_loop;

    kinv = ginvmod(stoi(k), e);
    a = gmul(inv2, gadd(kinv, n1));
    b = gsub(gsqr(a), modulus);
    b = Fp_sqrt(b, e);
    if (b == NULL) {
      continue;
    }

    tk = z_pvalrem(k, gen_2, &kk);
    pow2tk1 = shifti(gen_1, tk + 1);
    pow2v = shifti(gen_1, u - tk);
    a = gmod(gsub(gmulgs(n1, k), ed1), pow2u);
    if (!gdvd(a, pow2tk1)) {
      continue;
    }
    a = shifti(a, -tk);
    a = gmod(gmul(a, ginvmod(stoi(kk), pow2v)), pow2v);
    b = gmod(gsub(gsqr(a), gmulgs(modulus,4)), pow2v);

    if (gequal0(b)) {
      gamma = (u - tk + 1)/2;
    }
    else {
      t = Z_pvalrem(b, gen_2, &bb);
      if (t & 1) {
        continue;
      }
      gamma = t/2;
    }
    
    if (gamma < treshold) {
      continue;
    }
    ctr++;
    if (gamma > gamma_best) {
      gamma_best = gamma;
      k_best = k;
    }
    roots = sort(sqrt_mod2(modulus, gamma));
    printf("[x] k = %ld\n"
           "    Number of shared lsb: %ld\n"
           "    p mod 2^%ld is one of the four values:\n",
           k, gamma, gamma);
    for(i = 1; i <= 4; i++) {
      pari_printf("    * %Ps\n", gel(roots, i));
    }
  }

  /* Print summary of results. */
  printf("[x] Number of k candidates: %ld\n"
         "    Highest number of lsb: %ld for k = %ld\n",
         ctr, gamma_best, k_best);

  /* Garbage cleaning */
  avma = av;
}

int factor_d_lsb(GEN modulus, GEN e, GEN d0, long u, long k_start, long k_end, GEN *p, GEN *q) {
  GEN kinv, inv2, a, b, bb, m, n1, p0e, q0e, p02w, p0m, ed1, pow2u, pow2tk1, pow2v, pow2w, roots;
  long k, kk, tk, t, i;
  int found = FALSE;
  pari_sp av = avma, start_loop;

  pow2u = shifti(gen_1, u);
  ed1 = gmod(gsub(gmul(e, d0), gen_1), pow2u);
  inv2 = ginvmod(gen_2, e);
  n1 = gadd(modulus, gen_1);

  /* 
   * We go through all possible values for k in [1, e - 1].
   * The search can be reduced on the command line
   * with the options `--kstart` and `--kend`.
   */
  if (k_start < 1 || k_start >= gtolong(e)) {
    /* k_start must be in [1, e - 1] */
    k_start = 1;
  }
  if (k_end < 2 || k_end > gtolong(e)) {
    /* k_end must be in [2, e] */
    k_end = gtolong(e);
  }
  if (k_end <= k_start) {
    /* We must have k_start < k_end. */
    k_end = k_start + 1;
  }
  
  start_loop = avma;
  for(k = k_start; k < k_end; k++) {
    /* Garbage cleaning */
    avma = start_loop;

    if (verb) {
      fprintf(stderr, "[x] Test k = %ld (max: %ld)\n", k, k_end - 1);
    }

    /*
     * First part:
     * we look for p mod e and q mod e.
     */

    kinv = ginvmod(stoi(k), e);
    a = gmul(inv2, gadd(kinv, n1));
    b = gsub(gsqr(a), modulus);
    b = Fp_sqrt(b, e);
    /* We can discard a wrong candidate for k if there is no square roots. */
    if (b == NULL) {
      if (verb) {
        fprintf(stderr, "    -> Skipped: No candidate for p mod e.\n");
      }
      continue;
    }
    p0e = gmod(gadd(a, b), e);
    q0e = gmod(gsub(a, b), e);

    /* 
     * Second part:
     * we look for p mod 2^w with w <= u
     */

    /* Write k = 2^tk * kk, kk odd */
    tk = z_pvalrem(k, gen_2, &kk);
    pow2tk1 = shifti(gen_1, tk + 1);
    pow2v = shifti(gen_1, u - tk);
    a = gmod(gsub(gmulgs(n1, k), ed1), pow2u);
    /* If k is correct, then a = k*(p + q) mod 2^(u - tk) and is divisible by 2^(tk + 1) */
    if (!gdvd(a, pow2tk1)) {
      if (verb) {
        fprintf(stderr, "    -> Skipped: Candidate for (p + q) mod 2^u not divisible by 2.\n");
      }
      continue;
    }
    a = shifti(a, -tk);
    a = gmod(gmul(a, ginvmod(stoi(kk), pow2v)), pow2v);
    b = gmod(gsub(gsqr(a), gmulgs(modulus, 4)), pow2v);

    /* 
     * At this point, we have:
     *   a = (p + q) mod 2^(u - tk) and
     *   b = (p - q)^2 mod 2^(u - tk)
     * We look for square roots of b.
     * 
     * If b is 0, then p and q share their (u - tk)/2 least significant bits at least.
     * Then we are able to find p mod 2^((u - tk)/2).
     * Successful factorization with Coppersmith means that u should be at least the size of the primes p and q.
     * We dismiss this case, the tool `factor_shared_lsb` can be used if more than half of the bits are shared.
     * 
     * Otherwise, write b = 2^t*bb with bb odd.
     * Then, if bb mod 8 = 1, we have exactly 4 roots and we can get p mod 2^(u - tk - t/2).
     * Note that if t is odd, there are no solutions:
     * if p = p1*2^gamma + ell and q = q1*2^gamma + ell (with ell the gamma least significants in common),
     * then (p - q)^2 = (p1 - q1)^2 * 2^(2*gamma).
     * So the value t reveals the number of shared least significant bits gamma = t/2.
     */

    if (gequal0(b)) {
      if (verb) {
        fprintf(stderr, "    -> Skipped: Primes might share their %ld lsb, try the factor_shared_lsb attack.\n", (u - tk)/2);
      }
      continue;
    }

    /* b = 2^t*bb with bb odd */
    t = Z_pvalrem(b, gen_2, &bb);
    
    /* If t is odd, there is no solution */
    if (t & 1) {
      if (verb) {
        fprintf(stderr, "    -> Skipped: Candidate for (p - q)^2 mod 2^v cannot be a square.\n");
      }
      continue;
    }
    
    /* 
     * If modulus mod 4 = 3, we know for sure that p and q share only the least significant bit.
     * But if modulus mod 4 = 1, they have at least the last two significants bits in common.
     * If k is correctly guessed, then we can deduce the exact number.
     */
    if (verb) {
      fprintf(stderr, "    -> If k is correct, p and q have their %ld least significant bits in common.\n", t/2);
    }

    /* Extreme case: calculating roots mod 2 or 4 is useless to run the attack. */
    if (u - tk - t < 3) {
      if (verb) {
        fprintf(stderr, "    -> Skipped: Calculating roots mod 2 or mod 4 is useless.\n");
      }
      continue;
    }

    /* We find the 4 roots of bb mod 2^(u - tk - t) */
    roots = sqrt_mod2(bb, u - tk - t);
    
    /* No roots found if bb mod 8 != 1 */
    if (roots == NULL) {
      if (verb) {
        fprintf(stderr, "    -> Skipped: Candidate for (p - q)^2 mod 2^w cannot be a square.\n");
      }
      continue;
    }

    /* 
     * Now the last part.
     * The four roots are candidates either for p mod 2^w or q mod 2^w.
     * We combine with p mod e and q mod e using CRT.
     * So we have in total 8 candidates for p mod (e*2^w).
     * We use the function `factor_p_low` to apply Coppersmith method.
     */

    pow2w = shifti(gen_1, u - tk - t/2);
    m = gmul(e, pow2w);
    if (verb) {
      pari_fprintf(stderr, "    -> Trying Coppersmith with p mod (%Ps*2^%ld), a %ld-bit integer.\n", e, u - tk - t/2, logint(m, gen_2) + 1);
    }
   
    for(i = 1; i <= 4; i++) {
      b = shifti(gel(roots, i), t/2);
      /* Here, (a + b)/2 is a candidate for p mod 2^(u - tk - t/2) */
      p02w = gmod(shifti(gadd(a, b), -1), pow2w);

      /* We combine with p mod e */
      p0m = Z_chinese(p0e, p02w, e, pow2w);
      found = factor_p_low(modulus, p0m, gmul(e, pow2w), p, q);
      if (found) {
        goto end;
      }
      
      /* Second try with q mod e */
      p0m = Z_chinese(q0e, p02w, e, pow2w);
      found = factor_p_low(modulus, p0m, gmul(e, pow2w), p, q);
      if (found) {
        goto end;
      }
    }
  }

end:
  /* Garbage cleaning */
  if (found) {
    gerepileall(av, 2, p, q);
  }
  else {
    avma = av;
  }

  return found;
}
