/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#ifndef _CONFIG_H
#define _CONFIG_H

/*
 * You can modify default constant values used in the programs.
 * Beware that it could have a significative impact on the performance.
 * Change them only if you know what you are doing.
 * 
 * Some of these values can be changed with a command line option
 * during the execution.
 */

/* PARI init */
#define PARISIZE 1000000000
#define MAXPRIME 2

/* small modulus factorization */
#define SMALL_MODULUS_NBITS_BOUND 200

/* Close primes (Fermat) configuration */
#define FERMAT_BOUND 50000

/* Wiener configuration */
#define WIENER_MAX_CVG 1000

/* Prime factor recovery */
#define PRIME_RECOVERY_MAX_ITER 1000

/* p+1 and p-1 factorization configuration */
#define P_PM_1_MAX_ATTEMPTS 5
#define P_PM_1_PRIME_BOUND (1L << 16)
#define P_PM_1_NBITS_BOUND 64

/* 4p-1 factorization configuration */
#define CM_ANOMALOUS_MAX_ATTEMPTS 5
#define CM_ANOMALOUS_DISC_BOUND 64

#endif
