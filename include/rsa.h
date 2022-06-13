/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#ifndef _RSA_H
#define _RSA_H

#include <pari/pari.h>
#include "config.h"

#define TRUE 1
#define FALSE 0

extern int verb;

/* Factorization of a single RSA modulus */
int factor_cm_anomalous_core(GEN modulus, long d, GEN *p, GEN *q);
int factor_cm_anomalous(GEN modulus, GEN *p, GEN *q, int max_disc);
int factor_shared_lsb(GEN modulus, GEN *p, GEN *q);
int factor_close_primes(GEN modulus, GEN *p, GEN *q, const int max);
int factor_p_plus_minus_one(GEN modulus, GEN *p, GEN *q, GEN maxprime, long logbound);
int factor_small_d(GEN n, GEN e, GEN *d, GEN *p, GEN *q);
int factor_small_modulus(GEN modulus, GEN *p, GEN *q);
int factor_square_modulus(GEN modulus, GEN *p, GEN *q);
int factor_wiener(GEN modulus, GEN e, GEN *d, GEN *p, GEN *q);

/* Factorization of a single RSA modulus with Coppersmith method */
int factor_p_hi(GEN modulus, GEN p1, GEN m, GEN *p, GEN *q);
int factor_p_low(GEN modulus, GEN p0, GEN m, GEN *p, GEN *q);
int factor_d_lsb(GEN modulus, GEN e, GEN d0, long u, long k_start, long k_end, GEN *p, GEN *q);
void k_detect(GEN modulus, GEN e, GEN d0, long u, long treshold);

/* Utils */
GEN getseed();
int prime_factor_recovery(GEN modulus, GEN e, GEN d, const int n_iter, GEN *p, GEN *q);
void ladder(GEN scalar, GEN x0, GEN A, GEN B, GEN *res_x, GEN *res_z);
GEN sqrt_mod2(GEN a, long u);

#endif