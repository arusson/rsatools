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
  fprintf(stderr, "Usage: ./rsa_partial_p -n <modulus> -e <public exponent> -d <lowest bits of d> -l <number of bits known>\n"
                  "  -n, --modulus VAL      Modulus\n"
                  "  -e VAL                 Public exponent\n"
                  "  -d, --d0 VAL           Known lowest bits of d\n"
                  "  -l, --ell VAL          Number of bits known of d\n"
                  "  --kstart VAL           1 < kstart < e (optional)\n"
                  "  --kend VAL             1 < kend < e (optional)\n"
                  "  --kdetect VAL          Detect k value (VAL is the mimimal number of shared lsb by the prime factors\n"
                  "  -h --help              Print help\n"
                  "  -v, --verbose          More verbosity\n"
  );
}

int main(int argc, char *argv[]) {
  GEN modulus = NULL, p, q, e = NULL, d0 = NULL;
  long modulus_nbits, ell = -1, treshold = -1;
  int opt, k_start = -1, k_end = -1, found = FALSE;
  char options[] = ":n:e:d:l:vh";

  static struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"modulus", required_argument, NULL, 'n'},
    {"d0", required_argument, NULL, 'd'},
    {"ell", required_argument, NULL, 'l'},
    {"kstart", required_argument, NULL, 'k'},
    {"kend", required_argument, NULL, 'K'},
    {"kdetect", required_argument, NULL, 'D'},
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
      case 'e':
        e = gp_read_str(optarg);
        break;
      case 'd':
        d0 = gp_read_str(optarg);
        break;
      case 'l':
        ell = atol(optarg);
        break;
      case 'k':
        k_start = atol(optarg);
        break;
      case 'K':
        k_end = atol(optarg);
        break;
      case 'D':
        treshold = atol(optarg);
        break;
      case '?':
        fprintf(stderr, "Unknown option: %c\n", optopt);
        usage();
        goto end;
      case ':':
        fprintf(stderr, "Missing argument for option %c\n", optopt);
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

  if (d0 == NULL) {
    fprintf(stderr, "[!] Lowest bits of d must be provided\n");
    usage();
    goto end;
  }

  if (e == NULL) {
    fprintf(stderr, "[!] Public exponent must be provided\n");
    usage();
    goto end;
  }

  if (ell == -1) {
    fprintf(stderr, "[!] Number of bits of d known must be provided\n");
    usage();
    goto end;
  }

  modulus_nbits = logint(modulus, gen_2) + 1;
  if (verb) {
    fprintf(stderr, "[!] Modulus bit length: %ld\n", modulus_nbits);
  }

  /* For option `--kdetect`, we do not run the attack */
  if (treshold != -1) {
    if (mod4(modulus) == 1) {
      k_detect(modulus, e, d0, ell, treshold);
    }
    else {
      fprintf(stderr, "[!] Option `--kdetect` cannot be used if n mod 4 = 3\n");
    }
  }
  else {
    found = factor_d_lsb(modulus, e, d0, ell, k_start, k_end, &p, &q);
    if (found) {
      print_success(p, q);
    }
  }

end:
  pari_close();
  return 0;
}
