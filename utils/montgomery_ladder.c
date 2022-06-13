/* 
 * rsatools, a set of cryptanalysis tools against RSA
 * Copyright (C) 2022 A. Russon
 */

#include <pari/pari.h>

/*
 * http://hyperelliptic.org/EFD/g1p/auto-shortw-xz.html#doubling-dbl-2002-it-2
 */
void dbl_xz(GEN xx1, GEN zz1, GEN A, GEN B, GEN *xx3, GEN *zz3) {
  GEN t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13;
  pari_sp av = avma;

  t1 = gsqr(xx1);
  t2 = gsqr(zz1);
  t3 = gmul(A, t2);
  t4 = gsub(t1, t3);
  t5 = gsqr(t4);
  t6 = gmul(B, t2);
  t7 = gmul(xx1, zz1);
  t8 = gmul(t6,t7);
  t9 = gmulgs(t8, 8);
  
  *xx3 = gsub(t5, t9);
  t10 = gadd(t1, t3);
  t11 = gmul(t7, t10);
  t12 = gmul(t2,t6);
  t13 = gadd(t11, t12);
  *zz3 = gmulgs(t13, 4);

  /* Garbage cleaning */
  gerepileall(av, 2, xx3, zz3);
}

/*
 * http://hyperelliptic.org/EFD/g1p/auto-shortw-xz.html#diffadd-mdadd-2002-it-3
 */
void add_xz(GEN xx2, GEN zz2, GEN xx3, GEN zz3, GEN xx1, GEN A, GEN B, GEN *xx5, GEN *zz5) {
  GEN t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14;
  pari_sp av = avma;

  t1 = gmul(xx2, xx3);
  t2 = gmul(zz2, zz3);
  t3 = gmul(xx2, zz3);
  t4 = gmul(zz2, xx3);
  t5 = gmul(A, t2);
  t6 = gsub(t1, t5);
  t7 = gsqr(t6);
  t8 = gmul(B, t2);
  t9 = gmulgs(t8, 4);
  t10 = gadd(t3, t4);
  t11 = gmul(t9, t10);
  t12 = gsub(t7, t11);
  *xx5 = t12;
  t13 = gsub(t3, t4);
  t14 = gsqr(t13);
  *zz5 = gmul(xx1, t14);

  /* Garbage collection */
  gerepileall(av, 2, xx5, zz5);
}

void ladder(GEN scalar, GEN x0, GEN A, GEN B, GEN *res_x, GEN *res_z) {
  GEN xx1, zz1, xx2, zz2;
  long i, bit, len;
  pari_sp av = avma;

  len = logint(scalar, gen_2) + 1;
  xx1 = x0;
  zz1 = gen_1;
  dbl_xz(xx1, zz1, A, B, &xx2, &zz2);
  for (i = len - 2; i >= 0; i--) {
    bit = bittest(scalar, i);
    if (bit == 1) {
      add_xz(xx1, zz1, xx2, zz2, x0, A, B, &xx1, &zz1);
      dbl_xz(xx2, zz2, A, B, &xx2, &zz2);
    }
    else {
      add_xz(xx1, zz1, xx2, zz2, x0, A, B, &xx2, &zz2);
      dbl_xz(xx1, zz1, A, B, &xx1, &zz1);
    }
    if (gc_needed(av, 1)) {
      gerepileall(av, 4, &xx1, &zz1, &xx2, &zz2);
    }
  }

  /* Garbage cleaning: we keep (xx1, zz1) on the stack */
  gerepileall(av, 2, &xx1, &zz1);
  *res_x = xx1;
  *res_z = zz1;
}
