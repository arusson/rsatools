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

void usage() {
  fprintf(stderr, "rsatools version 0.1 of 2022-08-21\n"
                  "Usage: ./rsa_partial_p -n <modulus> [OPTIONS]\n"
                  "  -n, --modulus VAL      Modulus (mandatory)\n"
                  "The prime p partially known has the form p1*m + p0\n"
                  "Choose amongst one of the two following options:\n"
                  "  --p0 VAL               Known lowest part of p\n"
                  "  --p1 VAL               Known highest part of p\n"
                  "The value m can be provided in two ways:\n"
                  "  -m VAL                 Value of m\n"
                  "  -l VAL                 Shortcut for m=2^l\n\n"
                  "  -h --help              Print help\n"
                  "  -v, --verbose          More verbosity\n"
  );
}

int main(int argc, char *argv[]) {
  GEN modulus = NULL, p, q, m = NULL, p_part = NULL;
  char options[] = ":n:m:l:vh";
  int opt, hi = FALSE, found = FALSE;
  long modulus_nbits, ell = -1;

  static struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"modulus", required_argument, NULL, 'n'},
    {"p0", required_argument, NULL, 'L'},
    {"p1", required_argument, NULL, 'H'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

  /* Initialization */
  pari_init(PARISIZE, MAXPRIME);

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
      case 'H':
        if (p_part == NULL) {
          p_part = gp_read_str(optarg);
          hi = TRUE;
        }
        else {
          usage();
          goto end;
        }
        break;
      case 'L':
        if (p_part == NULL) {
          p_part = gp_read_str(optarg);
        }
        else {
          usage();
          goto end;
        }
        break;
      case 'm':
        if (ell == -1) {
          m = gp_read_str(optarg);
        }
        else {
          usage();
          goto end;
        }
        break;
      case 'l':
        if (m == NULL) {
          ell = atol(optarg);
        }
        else {
          usage();
          goto end;
        }
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

  if (p_part == NULL) {
    fprintf(stderr, "[!] p0 or p1 must be provided\n");
    usage();
    goto end;
  }

  if (m == NULL && ell == -1) {
    fprintf(stderr, "The value for m must be provided\n");
    usage();
    goto end;
  }

  modulus_nbits = logint(modulus, gen_2) + 1;
  if (verb) {
    fprintf(stderr, "[!] Modulus bit length: %ld\n", modulus_nbits);
  }

  if (ell != -1) {
    m = shifti(gen_1, ell);
  }

  if (hi) {
    found = factor_p_hi(modulus, p_part, m, &p, &q);
  }
  else {
    found = factor_p_low(modulus, p_part, m, &p, &q);
  }
  
  if (found) {
    print_success(p, q);
  }

end:
  pari_close();
  return 0;
}