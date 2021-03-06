#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "randombytes.h"
#include "api.h"
#include "params.h"
#include "mq.h"
#include "gf31.h"
#include "fips202.h"

static void HR(unsigned char* R, const unsigned char* sk,
	const unsigned char* m, const unsigned int mlen)
{
	uint64_t s_inc[26];

	shake256_inc_init(s_inc);
	shake256_inc_absorb(s_inc, sk, SK_BYTES);
	shake256_inc_absorb(s_inc, m, mlen);
	shake256_inc_finalize(s_inc);
	shake256_inc_squeeze(R, HASH_BYTES, s_inc);
}

static void Hdigest(unsigned char* D,
	const unsigned char* pk, const unsigned char* R,
	const unsigned char* m, const unsigned int mlen)
{
	uint64_t s_inc[26];

	shake256_inc_init(s_inc);
	shake256_inc_absorb(s_inc, pk, PK_BYTES);
	shake256_inc_absorb(s_inc, R, HASH_BYTES);
	shake256_inc_absorb(s_inc, m, mlen);
	shake256_inc_finalize(s_inc);
	shake256_inc_squeeze(D, HASH_BYTES, s_inc);
}

static void Hsigma0(unsigned char* sigma0, const unsigned char* commits)
{
	shake256(sigma0, HASH_BYTES, commits, HASH_BYTES * ROUNDS * 2);
}

/* Takes two arrays of N packed elements and an array of M packed elements,
   and computes a HASH_BYTES commitment. */
static void com_0(unsigned char* c,
	const unsigned char* rho,
	const unsigned char* inn, const unsigned char* inn2,
	const unsigned char* inm)
{
	uint64_t s_inc[26];

	shake256_inc_init(s_inc);
	shake256_inc_absorb(s_inc, rho, HASH_BYTES);
	shake256_inc_absorb(s_inc, inn, NPACKED_BYTES);
	shake256_inc_absorb(s_inc, inn2, NPACKED_BYTES);
	shake256_inc_absorb(s_inc, inm, MPACKED_BYTES);
	shake256_inc_finalize(s_inc);
	shake256_inc_squeeze(c, HASH_BYTES, s_inc);
}

/* Takes an array of N packed elements and an array of M packed elements,
   and computes a HASH_BYTES commitment. */
static void com_1(unsigned char* c,
	const unsigned char* rho,
	const unsigned char* inn, const unsigned char* inm)
{
	uint64_t s_inc[26];

	shake256_inc_init(s_inc);
	shake256_inc_absorb(s_inc, rho, HASH_BYTES);
	shake256_inc_absorb(s_inc, inn, NPACKED_BYTES);
	shake256_inc_absorb(s_inc, inm, MPACKED_BYTES);
	shake256_inc_finalize(s_inc);
	shake256_inc_squeeze(c, HASH_BYTES, s_inc);
}

/*
 * Generates an MQDSS key pair.
 */
int crypto_sign_keypair(unsigned char* pk, unsigned char* sk)
{
	signed char F[F_LEN];
	unsigned char skbuf[SEED_BYTES * 2];
	gf31 sk_gf31[N];
	gf31 pk_gf31[M];

	// Expand sk to obtain a seed for F and the secret input s.
	// We also expand to obtain a value for sampling r0, t0 and e0 during
	//  signature generation, but that is not relevant here.
	randombytes(sk, SEED_BYTES);
	shake256(skbuf, SEED_BYTES * 2, sk, SEED_BYTES);

	memcpy(pk, skbuf, SEED_BYTES);
	gf31_nrand_schar(F, F_LEN, pk, SEED_BYTES);
	gf31_nrand(sk_gf31, N, skbuf + SEED_BYTES, SEED_BYTES);
	MQ(pk_gf31, sk_gf31, F);
	vgf31_unique(pk_gf31, pk_gf31);
	gf31_npack(pk + SEED_BYTES, pk_gf31, M);

	return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t* sig, size_t* siglen,
	const uint8_t* m, size_t mlen, const uint8_t* sk)
{
	signed char F[F_LEN];
	unsigned char skbuf[SEED_BYTES * 4];
	gf31 pk_gf31[M];
	unsigned char pk[SEED_BYTES + MPACKED_BYTES];
	// Concatenated for convenient hashing.
	unsigned char D_sigma0_h0_sigma1[HASH_BYTES * 3 + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES)];
	unsigned char* D = D_sigma0_h0_sigma1;
	unsigned char* sigma0 = D_sigma0_h0_sigma1 + HASH_BYTES;
	unsigned char* h0 = D_sigma0_h0_sigma1 + 2 * HASH_BYTES;
	unsigned char* t1packed = D_sigma0_h0_sigma1 + 3 * HASH_BYTES;
	unsigned char* e1packed = D_sigma0_h0_sigma1 + 3 * HASH_BYTES + ROUNDS * NPACKED_BYTES;
	uint64_t shakestate[25] = { 0 };
	unsigned char shakeblock[SHAKE256_RATE];
	unsigned char h1[((ROUNDS + 7) & ~7) >> 3];
	unsigned char rnd_seed[HASH_BYTES + SEED_BYTES];
	unsigned char rho[2 * ROUNDS * HASH_BYTES];
	unsigned char* rho0 = rho;
	unsigned char* rho1 = rho + ROUNDS * HASH_BYTES;
	gf31 sk_gf31[N];
	gf31 rnd[(2 * N + M) * ROUNDS];  // Concatenated for easy RNG.
	gf31* r0 = rnd;
	gf31* t0 = rnd + N * ROUNDS;
	gf31* e0 = rnd + 2 * N * ROUNDS;
	gf31 r1[N * ROUNDS];
	gf31 t1[N * ROUNDS];
	gf31 e1[M * ROUNDS];
	gf31 gx[M * ROUNDS];
	unsigned char packbuf0[NPACKED_BYTES];
	unsigned char packbuf1[NPACKED_BYTES];
	unsigned char packbuf2[MPACKED_BYTES];
	unsigned char c[HASH_BYTES * ROUNDS * 2];
	gf31 alpha;
	int alpha_count = 0;
	unsigned char b;
	int i, j;

	shake256(skbuf, SEED_BYTES * 4, sk, SEED_BYTES);

	gf31_nrand_schar(F, F_LEN, skbuf, SEED_BYTES);

	HR(sig, sk, m, mlen);

	memcpy(pk, skbuf, SEED_BYTES);
	gf31_nrand(sk_gf31, N, skbuf + SEED_BYTES, SEED_BYTES);
	MQ(pk_gf31, sk_gf31, F);
	vgf31_unique(pk_gf31, pk_gf31);
	gf31_npack(pk + SEED_BYTES, pk_gf31, M);

	Hdigest(D, pk, sig, m, mlen);

	sig += HASH_BYTES;  // Compensate for prefixed R.

	memcpy(rnd_seed, skbuf + 2 * SEED_BYTES, SEED_BYTES);
	memcpy(rnd_seed + SEED_BYTES, D, HASH_BYTES);
	shake256(rho, 2 * ROUNDS * HASH_BYTES, rnd_seed, SEED_BYTES + HASH_BYTES);

	memcpy(rnd_seed, skbuf + 3 * SEED_BYTES, SEED_BYTES);
	memcpy(rnd_seed + SEED_BYTES, D, HASH_BYTES);
	gf31_nrand(rnd, (2 * N + M) * ROUNDS, rnd_seed, SEED_BYTES + HASH_BYTES);

	for (i = 0; i < ROUNDS; i++) {
		for (j = 0; j < N; j++) {
			r1[j + i * N] = 31 + sk_gf31[j] - r0[j + i * N];
		}
		G(gx + i * M, t0 + i * N, r1 + i * N, F);
	}
	for (i = 0; i < ROUNDS * M; i++) {
		gx[i] += e0[i];
	}
	for (i = 0; i < ROUNDS; i++) {
		gf31_npack(packbuf0, r0 + i * N, N);
		gf31_npack(packbuf1, t0 + i * N, N);
		gf31_npack(packbuf2, e0 + i * M, M);
		com_0(c + HASH_BYTES * (2 * i + 0), rho0 + i * HASH_BYTES, packbuf0, packbuf1, packbuf2);
		vgf31_shorten_unique(r1 + i * N, r1 + i * N);
		vgf31_shorten_unique(gx + i * M, gx + i * M);
		gf31_npack(packbuf0, r1 + i * N, N);
		gf31_npack(packbuf1, gx + i * M, M);
		com_1(c + HASH_BYTES * (2 * i + 1), rho1 + i * HASH_BYTES, packbuf0, packbuf1);
	}

	Hsigma0(sigma0, c);
	shake256_absorb(shakestate, D_sigma0_h0_sigma1, 2 * HASH_BYTES);
	shake256_squeezeblocks(shakeblock, 1, shakestate);

	memcpy(h0, shakeblock, HASH_BYTES);

	memcpy(sig, sigma0, HASH_BYTES);
	sig += HASH_BYTES;  // Compensate for sigma_0.

	for (i = 0; i < ROUNDS; i++) {
		do {
			alpha = shakeblock[alpha_count] & 31;
			alpha_count++;
			if (alpha_count == SHAKE256_RATE) {
				alpha_count = 0;
				shake256_squeezeblocks(shakeblock, 1, shakestate);
			}
		} while (alpha == 31);
		for (j = 0; j < N; j++) {
			t1[i * N + j] = alpha * r0[j + i * N] - t0[j + i * N] + 31;
		}
		MQ(e1 + i * M, r0 + i * N, F);
		for (j = 0; j < N; j++) {
			e1[i * N + j] = alpha * e1[j + i * M] - e0[j + i * M] + 31;
		}
		vgf31_shorten_unique(t1 + i * N, t1 + i * N);
		vgf31_shorten_unique(e1 + i * N, e1 + i * N);
	}
	gf31_npack(t1packed, t1, N * ROUNDS);
	gf31_npack(e1packed, e1, M * ROUNDS);

	memcpy(sig, t1packed, NPACKED_BYTES * ROUNDS);
	sig += NPACKED_BYTES * ROUNDS;
	memcpy(sig, e1packed, MPACKED_BYTES * ROUNDS);
	sig += MPACKED_BYTES * ROUNDS;

	shake256(h1, ((ROUNDS + 7) & ~7) >> 3, D_sigma0_h0_sigma1, 3 * HASH_BYTES + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES));

	for (i = 0; i < ROUNDS; i++) {
		b = (h1[(i >> 3)] >> (i & 7)) & 1;
		if (b == 0) {
			gf31_npack(sig, r0 + i * N, N);
		}
		else if (b == 1) {
			gf31_npack(sig, r1 + i * N, N);
		}
		memcpy(sig + NPACKED_BYTES, c + HASH_BYTES * (2 * i + (1 - b)), HASH_BYTES);
		memcpy(sig + NPACKED_BYTES + HASH_BYTES, rho + (i + b * ROUNDS) * HASH_BYTES, HASH_BYTES);
		sig += NPACKED_BYTES + 2 * HASH_BYTES;
	}

	*siglen = SIG_LEN;

	return 0;
}

//static void debug_print(const unsigned char* buf, size_t len) {
//	for (size_t j = 0; j < len; j++) {
//		printf("%02x", buf[j]);
//	}
//	printf("\n");
//}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_forge(uint8_t* sig, size_t* siglen,
	const uint8_t* m, size_t mlen, const uint8_t* pk)
{
	signed char F[F_LEN];
	unsigned char skbuf[SEED_BYTES * 4];
	gf31 pk_gf31[M];
	// Concatenated for convenient hashing.
	unsigned char D_sigma0_h0_sigma1[HASH_BYTES * 3 + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES)];
	unsigned char* D = D_sigma0_h0_sigma1;
	unsigned char* sigma0 = D_sigma0_h0_sigma1 + HASH_BYTES;
	unsigned char* h0 = D_sigma0_h0_sigma1 + 2 * HASH_BYTES;
	unsigned char* t1packed = D_sigma0_h0_sigma1 + 3 * HASH_BYTES;
	unsigned char* e1packed = D_sigma0_h0_sigma1 + 3 * HASH_BYTES + ROUNDS * NPACKED_BYTES;
	uint64_t shakestate[25] = { 0 };
	unsigned char shakeblock[SHAKE256_RATE];
	unsigned char h1[((ROUNDS + 7) & ~7) >> 3];
	unsigned char rnd_seed[HASH_BYTES + SEED_BYTES];
	unsigned char rho[2 * ROUNDS * HASH_BYTES];
	unsigned char* rho0 = rho;
	unsigned char* rho1 = rho + ROUNDS * HASH_BYTES;
	unsigned char* org_sig = sig;
	const unsigned char* org_pk = pk;
	gf31 sk_gf31[N];
	gf31 rnd[(2 * N + M) * ROUNDS];  // Concatenated for easy RNG.
	gf31* r0 = rnd;
	gf31* t0 = rnd + N * ROUNDS;
	gf31* e0 = rnd + 2 * N * ROUNDS;
	gf31 r1[N * ROUNDS];
	gf31 t1[N * ROUNDS];
	gf31 e1[M * ROUNDS];
	gf31 t1_real[N * ROUNDS];
	gf31 e1_real[M * ROUNDS];
	gf31 t1_send[N * ROUNDS];
	gf31 e1_send[M * ROUNDS];
	gf31 gx[M * ROUNDS];
	gf31 gx2[M * ROUNDS];
	gf31 y0[M * ROUNDS];
	gf31 y1[M * ROUNDS];
	unsigned char packbuf0[NPACKED_BYTES];
	unsigned char packbuf1[NPACKED_BYTES];
	unsigned char packbuf2[MPACKED_BYTES];
	unsigned char c[HASH_BYTES * ROUNDS * 2];
	int alpha_count = 0;
	unsigned char b;
	int i, j;
	gf31 alphas[ROUNDS] = { 0, };

	//generate some garbage secret key s'
	shake256(skbuf, SEED_BYTES * 4, pk, SEED_BYTES);
	gf31_nrand(sk_gf31, N, skbuf + SEED_BYTES, SEED_BYTES);


	gf31_nrand_schar(F, F_LEN, pk, SEED_BYTES);
	pk += SEED_BYTES;
	gf31_nunpack(pk_gf31, pk, M);

	// fill rho with random values
	memcpy(rnd_seed, skbuf + 2 * SEED_BYTES, SEED_BYTES);
	memcpy(rnd_seed + SEED_BYTES, D, HASH_BYTES);
	shake256(rho, 2 * ROUNDS * HASH_BYTES, rnd_seed, SEED_BYTES + HASH_BYTES);

	// fill rnd with random values
	memcpy(rnd_seed, skbuf + 3 * SEED_BYTES, SEED_BYTES);
	memcpy(rnd_seed + SEED_BYTES, D, HASH_BYTES);
	gf31_nrand(rnd, (2 * N + M) * ROUNDS, rnd_seed, SEED_BYTES + HASH_BYTES);

	// guess for our malicous alpha'
	// this is random and exact value does not matter, could even be different for each round, but this would not change success probability
	gf31 alpha_guess = 12;
	// calculate r1 = sk' - r0
	for (i = 0; i < ROUNDS; i++) {
		for (j = 0; j < N; j++) {
			r1[j + i * N] = 31 + sk_gf31[j] - r0[j + i * N];
			// calculate t1' = alpha' * r0 - t0
			t1[i * N + j] = alpha_guess * r0[j + i * N] - t0[j + i * N] + 31;
		}
		vgf31_shorten_unique(r1 + i * N, r1 + i * N);
		vgf31_shorten_unique(t1 + i * N, t1 + i * N);
		// calculate G(t1',r1)
		G(gx + i * M, t1 + i * N, r1 + i * N, F);
		// calculate F(r0)
		MQ(y0 + i * M, r0 + i * N, F);
		// calculate F(r1)
		MQ(y1 + i * M, r1 + i * N, F);
		// calculate e1' = alpha' * F(r0) - e0
		for (j = 0; j < N; j++) {
			e1[i * N + j] = alpha_guess * y0[j + i * M] - e0[j + i * M] + 31;
		}
		vgf31_shorten_unique(e1 + i * N, e1 + i * N);
	}
	// calculate malicious commitment value for com1: alpha' * (v-F(r1)) - G(t1',r1) - alpha'*F(r0) + e0
	for (i = 0; i < ROUNDS * M; i++) {
		gx2[i] = alpha_guess * (31 + pk_gf31[i % M] - y1[i]) - gx[i] - alpha_guess * (y0[i]) + e0[i] + 31 + alpha_guess * 31;
	}
	for (i = 0; i < ROUNDS; i++) {
		// standard com0
		gf31_npack(packbuf0, r0 + i * N, N);
		gf31_npack(packbuf1, t0 + i * N, N);
		gf31_npack(packbuf2, e0 + i * M, M);
		com_0(c + HASH_BYTES * (2 * i + 0), rho0 + i * HASH_BYTES, packbuf0, packbuf1, packbuf2);
		// com1 deviates from protocol by commiting to (r1,  alpha' * (v-F(r1)) - G(t1',r1) - alpha'*F(r0) + e0) instead
		vgf31_shorten_unique(gx2 + i * M, gx2 + i * M);
		gf31_npack(packbuf0, r1 + i * N, N);
		gf31_npack(packbuf1, gx2 + i * M, M);
		com_1(c + HASH_BYTES * (2 * i + 1), rho1 + i * HASH_BYTES, packbuf0, packbuf1);
	}

	// hash the first message
	// debug out
	/*for (i = 0; i < ROUNDS; i++) {
		printf("round %d:\n", i);
		debug_print(c + HASH_BYTES * (2 * i + 0), HASH_BYTES);
		debug_print(c + HASH_BYTES * (2 * i + 1), HASH_BYTES);
	}*/
	Hsigma0(sigma0, c);

	int correct_guesses;
	unsigned long long int first_phase_try = 0;
	do {
		first_phase_try++;
		correct_guesses = 0;
		// calculate some "random" R, does not matter how
		// if we were unsucessful, pick new R, try again
		randombytes(org_sig, HASH_BYTES);
		Hdigest(D, org_pk, org_sig, m, mlen);

		// generate the first challenge
		shake256_absorb(shakestate, D_sigma0_h0_sigma1, 2 * HASH_BYTES);
		shake256_squeezeblocks(shakeblock, 1, shakestate);
		memcpy(h0, shakeblock, HASH_BYTES);
		// check how many alphas were guessed correctly
		alpha_count = 0;
		for (i = 0; i < ROUNDS; i++) {
			do {
				alphas[i] = shakeblock[alpha_count] & 31;
				alpha_count++;
				if (alpha_count == SHAKE256_RATE) {
					alpha_count = 0;
					shake256_squeezeblocks(shakeblock, 1, shakestate);
				}
			} while (alphas[i] == 31);
			if (alphas[i] == alpha_guess) {
				correct_guesses++;
			}
		}
		// do we have enough for the first phase?
		// e.g. for 20 total iterations we want at least 5 in the first phase
		// otherwise try again with new R
	} while (correct_guesses < FIRST_ROUND_GUESSES);
	printf("got first phase after %llu tries, starting second phase\n", first_phase_try);

	//debug_print(org_sig, HASH_BYTES);
	sig += HASH_BYTES; // compensate for R
	memcpy(sig, sigma0, HASH_BYTES);
	//debug_print(sigma0, HASH_BYTES);
	sig += HASH_BYTES;  // Compensate for sigma_0.
	//debug_print(D_sigma0_h0_sigma1, 2 * HASH_BYTES);

	// calculate (alpha * (v - F(r1)) - G(t1',r1)) - (alpha'*(v-F(r1)) - G(t1',r1) - alpha'*F(r0) + e0)
	// this is the value of e1 for the case that b=1, used below
	// also calculate the correct value of t1 and e1 based on the real alpha
	for (i = 0; i < ROUNDS; i++) {
		for (j = 0; j < M; j++) {
			gx2[i * N + j] = (alphas[i] * (31 + pk_gf31[j] - y1[i * N + j]) - gx[i * N + j]) - gx2[i * N + j] + 31*2;
			t1_real[i * N + j] = alphas[i] * r0[j + i * N] - t0[j + i * N] + 31;
			e1_real[i * N + j] = alphas[i] * y0[j + i * M] - e0[j + i * M] + 31;
		}
		vgf31_shorten_unique(gx2 + i * M, gx2 + i * M);
		vgf31_shorten_unique(t1_real + i * N, t1_real + i * N);
		vgf31_shorten_unique(e1_real + i * N, e1_real + i * N);
	}
	// fill the values we send with our malicious ones by default
	for (i = 0; i < ROUNDS * M; i++) {
		t1_send[i] = t1[i];
		e1_send[i] = e1[i];
	}

	// generate answers for second round
	for (unsigned long long int round2_try = 0; round2_try < (1ULL << (ROUNDS-correct_guesses)); round2_try++) {
		// for the rounds we did not cheat in the first phase, we generate challenges where we can answer either b=0 or b=1
		// the round2_try variable indicates the current configuration, if bit i of round2_try is 0, we try to answer b=0 in repetition i,
		// otherwise we try to answer b=1 in repetition i
		// this allows us to try 2^SECOND_ROUND_GUESSES combinations, of which we expect one to have the correct challenge when hashed

		unsigned int round2_fixes = 0;
		for (i = 0; i < ROUNDS; i++) {
			if (alphas[i] == alpha_guess) {
				// we have guessed alpha correctly, so we can answer both challenges
				// send t1' = alpha'*r0 - t0
				//      e1' = alpha'*F(r0) - e0
				// this is already in t1_send, e1_send, so we do nothing
			}
			else {
				if ((round2_try >> round2_fixes) & 1) {
					// this answer is valid when b=1
					// send t1' = alpha'*r0 - t0
					//      e1' = (alpha * (v - F(r1)) - G(t1',r1)) - ((alpha'*(v-F(r1)) - G(t1',r1) - alpha'*F(r0) + e0))
					memcpy(t1_send + i * M, t1 + i * M, M * sizeof(gf31));
					memcpy(e1_send + i * M, gx2 + i * M, M * sizeof(gf31));
				}
				else {
					// this answer is valid when b=0
					// send t1' = alpha*r0 - t0
					//      e1' = alpha*F(r0) - e0
					memcpy(t1_send + i * M, t1_real + i * M, M * sizeof(gf31));
					memcpy(e1_send + i * M, e1_real + i * M, M * sizeof(gf31));
				}
				round2_fixes++;
			}
		}
		gf31_npack(t1packed, t1_send, N * ROUNDS);
		gf31_npack(e1packed, e1_send, M * ROUNDS);

		shake256(h1, ((ROUNDS + 7) & ~7) >> 3, D_sigma0_h0_sigma1, 3 * HASH_BYTES + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES));
		round2_fixes = 0;
		unsigned char ok = 1;
		for (i = 0; i < ROUNDS; i++) {
			if (alphas[i] == alpha_guess)
				continue;
			b = (h1[(i >> 3)] >> (i & 7)) & 1;
			if (b != ((round2_try >> round2_fixes) & 1)) {
				ok = 0;
				break;
			}
			round2_fixes++;
		}
		if (ok) {
			memcpy(sig, t1packed, NPACKED_BYTES * ROUNDS);
			sig += NPACKED_BYTES * ROUNDS;
			memcpy(sig, e1packed, MPACKED_BYTES * ROUNDS);
			sig += MPACKED_BYTES * ROUNDS;
			printf("found a valid forgery after %llu tries, second phase done, building signature\n", round2_try);
			shake256(h1, ((ROUNDS + 7) & ~7) >> 3, D_sigma0_h0_sigma1, 3 * HASH_BYTES + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES));
			for (i = 0; i < ROUNDS; i++) {
				b = (h1[(i >> 3)] >> (i & 7)) & 1;
				//printf("%d: %d == %d, %d\n", i, alphas[i], alpha_guess, b);
				if (b == 0) {
					gf31_npack(sig, r0 + i * N, N);
				}
				else if (b == 1) {
					gf31_npack(sig, r1 + i * N, N);
				}
				memcpy(sig + NPACKED_BYTES, c + HASH_BYTES * (2 * i + (1 - b)), HASH_BYTES);
				memcpy(sig + NPACKED_BYTES + HASH_BYTES, rho + (i + b * ROUNDS) * HASH_BYTES, HASH_BYTES);
				sig += NPACKED_BYTES + 2 * HASH_BYTES;
			}
			*siglen = SIG_LEN;
			printf("verification of our forged signature returned %d\n", crypto_sign_verify(org_sig, SIG_LEN, m, mlen, org_pk));
			return 0;
		}
	}

	printf("got at the end of all possible challenges, no luck, please try again\n");

	return -1;
}


/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t* sig, size_t siglen,
	const uint8_t* m, size_t mlen, const uint8_t* pk)
{
	gf31 r[N];
	gf31 t[N];
	gf31 e[M];
	signed char F[F_LEN];
	gf31 pk_gf31[M];
	// Concatenated for convenient hashing.
	unsigned char D_sigma0_h0_sigma1[HASH_BYTES * 3 + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES)];
	unsigned char* D = D_sigma0_h0_sigma1;
	unsigned char* sigma0 = D_sigma0_h0_sigma1 + HASH_BYTES;
	unsigned char* h0 = D_sigma0_h0_sigma1 + 2 * HASH_BYTES;
	unsigned char* t1packed = D_sigma0_h0_sigma1 + 3 * HASH_BYTES;
	unsigned char* e1packed = D_sigma0_h0_sigma1 + 3 * HASH_BYTES + ROUNDS * NPACKED_BYTES;
	unsigned char h1[((ROUNDS + 7) & ~7) >> 3];
	unsigned char c[HASH_BYTES * ROUNDS * 2];
	memset(c, 0, HASH_BYTES * 2);
	gf31 x[N];
	gf31 y[M];
	gf31 z[M];
	unsigned char packbuf0[NPACKED_BYTES];
	unsigned char packbuf1[MPACKED_BYTES];
	uint64_t shakestate[25] = { 0 };
	unsigned char shakeblock[SHAKE256_RATE];
	int i, j;
	gf31 alpha;
	int alpha_count = 0;
	unsigned char b;

	if (siglen != SIG_LEN) {
		return -1;
	}

	Hdigest(D, pk, sig, m, mlen);

	sig += HASH_BYTES;

	gf31_nrand_schar(F, F_LEN, pk, SEED_BYTES);
	pk += SEED_BYTES;
	gf31_nunpack(pk_gf31, pk, M);

	memcpy(sigma0, sig, HASH_BYTES);


	shake256_absorb(shakestate, D_sigma0_h0_sigma1, 2 * HASH_BYTES);
	shake256_squeezeblocks(shakeblock, 1, shakestate);

	memcpy(h0, shakeblock, HASH_BYTES);

	sig += HASH_BYTES;

	memcpy(t1packed, sig, ROUNDS * NPACKED_BYTES);
	sig += ROUNDS * NPACKED_BYTES;
	memcpy(e1packed, sig, ROUNDS * MPACKED_BYTES);
	sig += ROUNDS * MPACKED_BYTES;

	shake256(h1, ((ROUNDS + 7) & ~7) >> 3, D_sigma0_h0_sigma1, 3 * HASH_BYTES + ROUNDS * (NPACKED_BYTES + MPACKED_BYTES));

	for (i = 0; i < ROUNDS; i++) {
		do {
			alpha = shakeblock[alpha_count] & 31;
			alpha_count++;
			if (alpha_count == SHAKE256_RATE) {
				alpha_count = 0;
				shake256_squeezeblocks(shakeblock, 1, shakestate);
			}
		} while (alpha == 31);
		b = (h1[(i >> 3)] >> (i & 7)) & 1;
		//printf("alpha: %d, b: %d\n", alpha, b);

		gf31_nunpack(r, sig, N);
		gf31_nunpack(t, t1packed + NPACKED_BYTES * i, N);
		gf31_nunpack(e, e1packed + MPACKED_BYTES * i, M);

		if (b == 0) {
			MQ(y, r, F);
			for (j = 0; j < N; j++) {
				x[j] = alpha * r[j] - t[j] + 31;
			}
			for (j = 0; j < N; j++) {
				y[j] = alpha * y[j] - e[j] + 31;
			}
			vgf31_shorten_unique(x, x);
			vgf31_shorten_unique(y, y);
			gf31_npack(packbuf0, x, N);
			gf31_npack(packbuf1, y, M);
			com_0(c + HASH_BYTES * (2 * i + 0), sig + HASH_BYTES + NPACKED_BYTES, sig, packbuf0, packbuf1);
		}
		else {
			MQ(y, r, F);
			G(z, t, r, F);
			for (j = 0; j < N; j++) {
				y[j] = alpha * (31 + pk_gf31[j] - y[j]) - z[j] - e[j] + 62;
			}
			vgf31_shorten_unique(y, y);
			gf31_npack(packbuf0, y, M);
			com_1(c + HASH_BYTES * (2 * i + 1), sig + HASH_BYTES + NPACKED_BYTES, sig, packbuf0);
		}
		memcpy(c + HASH_BYTES * (2 * i + (1 - b)), sig + NPACKED_BYTES, HASH_BYTES);
		sig += NPACKED_BYTES + 2 * HASH_BYTES;
	}

	//for (i = 0; i < ROUNDS; i++) {
	//	printf("round %d:\n", i);
	//	debug_print(c + HASH_BYTES * (2 * i + 0), HASH_BYTES);
	//	debug_print(c + HASH_BYTES * (2 * i + 1), HASH_BYTES);
	//}
	Hsigma0(c, c);
	if (memcmp(c, sigma0, HASH_BYTES)) {
		return 1;
	}

	return 0;
}

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk)
{
	size_t siglen;

	crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk);

	memmove(sm + SIG_LEN, m, mlen);
	*smlen = siglen + mlen;

	return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk)
{
	/* The API caller does not necessarily know what size a signature should be
	   but MQDSS signatures are always exactly SIG_LEN. */
	if (smlen < SIG_LEN) {
		memset(m, 0, smlen);
		*mlen = 0;
		return -1;
	}

	*mlen = smlen - SIG_LEN;

	if (crypto_sign_verify(sm, SIG_LEN, sm + SIG_LEN, (size_t)* mlen, pk)) {
		memset(m, 0, smlen);
		*mlen = 0;
		return -1;
	}

	/* If verification was successful, move the message to the right place. */
	memmove(m, sm + SIG_LEN, *mlen);

	return 0;
}
