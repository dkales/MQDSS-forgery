#ifndef MQDSS_PARAMS_H
#define MQDSS_PARAMS_H

#define N 48
#define M N
#define F_LEN (M * (((N * (N + 1)) >> 1) + N)) /* Number of elements in F */

// normally 135, reduced for testing
#define ROUNDS 40
// tradeoff between first and second rounds
#define FIRST_ROUND_GUESSES 11

/* Number of bytes that N, M and F_LEN elements require when packed into a byte
   array, 5-bit elements packed continuously. */
/* Assumes N and M to be multiples of 8 */
#define NPACKED_BYTES ((N * 5) >> 3)
#define MPACKED_BYTES ((M * 5) >> 3)
#define FPACKED_BYTES ((F_LEN * 5) >> 3)

#define HASH_BYTES 32
#define SEED_BYTES 16
#define PK_BYTES (SEED_BYTES + MPACKED_BYTES)
#define SK_BYTES SEED_BYTES

// R, sigma_0, ROUNDS * (t1, r{0,1}, e1, c, rho)
#define SIG_LEN (2 * HASH_BYTES + ROUNDS * (2*NPACKED_BYTES + MPACKED_BYTES + HASH_BYTES + HASH_BYTES))

#endif
