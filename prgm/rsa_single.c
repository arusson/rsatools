/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include <getopt.h>
#include "rsa.h"

int verb = FALSE;

void print_success(GEN p, GEN q) {
  pari_printf("p = %Ps\nq = %Ps\n", p, q);
}

void print_success_full(GEN p, GEN q, GEN d) {
  pari_printf("p = %Ps\n"
              "q = %Ps\n"
              "d = %Ps\n", p, q, d);
}

void usage() {
  fprintf(stderr, "rsatools version 0.1 of 2022-08-21\n"
                  "Usage: ./rsa_single -n <modulus> [OPTIONS]\n"
                  "List of options (values are expected in decimal):\n"
                  "  -n, --modulus          Modulus\n"
                  "  -e, --exponent         Public exponent\n"
                  "  -d,                    Private exponent (only for prime factor recovery)\n"
                  "  -v, --verbose          More verbosity\n"
                  "  --attack <attack name> Run a specific attack:\n"
                  "                           factor_small: for modulus less than 200 bits\n"
                  "                           factor_square: for modulus such that n = p^2\n"
                  "                           factor_small_d: the small private exponent attack, public exponent is needed\n"
                  "                           factor_wiener: the Wiener attack, public exponent is needed\n"
                  "                           factor_fermat: the Fermat attack, when prime factors are close\n"
                  "                           factor_shared_lsb: if prime factors have half of their least significant bits identical\n"
                  "                           factor_p_pm_1: the p-1 and p+1 methods\n"
                  "                           factor_cm: the 4p-1 factorization methods using elliptic curves\n"
                  "  --fermat-bound <val>   Default is 50000, increase the value if needed\n"
                  "  --p1-prime-bound <val> Bound on the prime factors of p-1 or p+1 (default is 2^16)\n"
                  "  --p1-nbits-bound <val> Bound on prime power factors of p-1 or p+1, value in bits (default is 64)\n"
                  "  --cm-disc <val>        For 4p-1 attack: to specify a CM-discriminant in absolute value (example: 11)\n"
                  "  --cm-disc-bound <val>  For 4p-1 attack: run the attack with discriminants between -3 and -val\n"
  );
}

int main(int argc, char *argv[]) {
  GEN seed, modulus = NULL, p, q, e = NULL, d = NULL;
  long close_primes_bound = FERMAT_BOUND;
  long p1_prime_bound = P_PM_1_PRIME_BOUND;
  long p1_nbits_bound = P_PM_1_NBITS_BOUND;
  long cm_disc_bound = CM_ANOMALOUS_DISC_BOUND;
  long disc = -1, modulus_nbits;
  int opt, found = FALSE;
  char options[] = ":n:e:d:vh";
  char *attack = NULL;

  static struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"modulus", required_argument, NULL, 'n'},
    {"exponent", required_argument, NULL, 'e'},
    {"fermat-bound", required_argument, NULL, 'Z'},
    {"p1-prime-bound", required_argument, NULL, 'Y'},
    {"p1-nbits-bound", required_argument, NULL, 'X'},
    {"cm-disc-bound", required_argument, NULL, 'W'},
    {"cm-disc", required_argument, NULL, 'D'},
    {"attack", required_argument, NULL, 'a'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

  /* Initialization */
  pari_init(PARISIZE, MAXPRIME);

  seed = getseed();
  setrand(seed);

  /* Process arguments */
  opt = getopt_long(argc, argv, options, long_options, NULL);
  while (opt != -1) {
    switch (opt) {
      case 'v':
        verb = TRUE;
        break;
      case 'h':
        usage();
        goto end;
      case 'n':
        modulus = gp_read_str(optarg);
        break;
      case 'e':
        e = gp_read_str(optarg);
        break;
      case 'd':
        d = gp_read_str(optarg);
        break;
      case 'D':
        disc = atol(optarg);
        break;
      case 'a':
        attack = optarg;
        break;
      case 'Z':
        close_primes_bound = atol(optarg);
        break;
      case 'Y':
        p1_prime_bound = atol(optarg);
        break;
      case 'X':
        p1_nbits_bound = atol(optarg);
        break;
      case 'W':
        cm_disc_bound = atol(optarg);
        break;
      case '?':
        fprintf(stderr, "Unknown option: %c\n", optopt);
        usage();
        goto end;
      case ':':
        fprintf(stderr, "Missing argument for option %c", optopt);
        usage();
        goto end;
    }
    opt = getopt_long(argc, argv, options, long_options, NULL);
  }

  if (modulus == NULL) {
    fprintf(stderr, "[!] Modulus must be provided\n");
    usage();
    goto end;
  }

  if (verb) {
    pari_fprintf(stderr, "[!] Random seed: %Ps\n", seed);
  }

  modulus_nbits = logint(modulus, gen_2) + 1;
  if (verb) {
    fprintf(stderr, "[!] Modulus bit length: %ld\n", modulus_nbits);
  }

  /* We run the prime factor recovery */
  if (e != NULL && d != NULL) {
    fprintf(stderr, "[x] Prime factor recovery...\n");
    found = prime_factor_recovery(modulus, e, d, PRIME_RECOVERY_MAX_ITER, &p, &q);
    if (found) {
      print_success(p, q);
      goto end;
    }
  }

  /* Run small modulus attack (n < 2^200 by default in config.h) */
  if (attack == NULL || !strcmp(attack, "factor_small")) {
    fprintf(stderr, "[x] Small modulus factorization...\n");
    if (modulus_nbits <= SMALL_MODULUS_NBITS_BOUND) {
      found = factor_small_modulus(modulus, &p, &q);
      if (found) {
        print_success(p, q);
        goto end;
      }
    }
    else {
      fprintf(stderr, "    Skipped: modulus is too big (%ld bits)\n", modulus_nbits);
    }
  }

  /* Run square modulus attack */
  if (attack == NULL || !strcmp(attack, "factor_square")) {
    fprintf(stderr, "[x] Square modulus factorization...\n");
    found = factor_square_modulus(modulus, &p, &q);
    if (found) {
      print_success(p, q);
      goto end;
    }
  }

  /* Run small d attack (in case Wiener did not work) */
  if (attack == NULL || !strcmp(attack, "factor_small_d")) {
    fprintf(stderr, "[x] Running small d attack...\n");
    if (e != NULL) {
      found = factor_small_d(modulus, e, &d, &p, &q);
      if (found) {
        print_success_full(p, q, d);
        goto end;
      }
    }
    else {
      fprintf(stderr, "    Skipped: public exponent not provided (use -e option)\n");
    }
  }

  /* Run Wiener attack */
  if (attack == NULL || !strcmp(attack, "factor_wiener")) {
    fprintf(stderr, "[x] Running Wiener attack...\n");
    if (e != NULL) {
      found = factor_wiener(modulus, e, &d, &p, &q);
      if (found) {
        print_success_full(p, q, d);
        goto end;
      }
      else if (d != NULL) {
        pari_printf("d = %Ps\nFAILURE to recover prime factors\n", d);
      }
    }
    else {
      fprintf(stderr, "    Skipped: public exponent not provided (use -e option)\n");
    }
  }

  /* Run close primes attack (Fermat) */
  if (attack == NULL || !strcmp(attack, "factor_fermat")) {
    fprintf(stderr, "[x] Running close primes attack...\n");
    found = factor_close_primes(modulus, &p, &q, close_primes_bound);
    if (found) {
      print_success(p, q);
      goto end;
    }
  }

  /* Run shared lsb attack */
  if (attack == NULL || !strcmp(attack, "factor_shared_lsb")) {  
    fprintf(stderr, "[x] Running shared LSB attack...\n");
    found = factor_shared_lsb(modulus, &p, &q);
    if (found) {
      print_success(p, q);
      goto end;
    }
  }

  /* Run p-1 and p+1 attack */
  if (attack == NULL || !strcmp(attack, "factor_p_pm_1")) {
    fprintf(stderr, "[x] Running p-1 and p+1 attack...\n");
    found = factor_p_plus_minus_one(modulus, &p, &q, stoi(p1_prime_bound), p1_nbits_bound);
    if (found) {
      print_success(p, q);
      goto end;
    }
  }

  /* Run 4p-1 attack */
  if (attack == NULL || !strcmp(attack, "factor_cm")) {
    fprintf(stderr, "[x] Running 4p-1 attack...\n");
    if (disc != -1) {
      found = factor_cm_anomalous_core(modulus, -disc, &p, &q);
    }
    else {
      found = factor_cm_anomalous(modulus, &p, &q, cm_disc_bound);
    }
    if (found) {
      print_success(p, q);
    }
  }

end:
  pari_close();

  return 0;
}