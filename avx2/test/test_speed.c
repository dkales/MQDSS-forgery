#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "../params.h"
#include "../randombytes.h"
#include "../api.h"
#include "../mq.h"
#include "../fips202.h"
#include "../sha3/KeccakHash.h"

#define NTESTS 1000
#define MLEN 32

static unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

static int cmp_llu(const void *a, const void*b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2) return l[llen / 2];
    else return (l[llen/2 - 1] + l[llen/2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc=0;
    size_t i;
    for(i = 0; i < tlen; i++) {
        acc += t[i];
    }
    return acc/(tlen);
}

static void print_results(const char *s, unsigned long long *t, size_t tlen, int mult)
{
  size_t i;
  printf("%s", s);
  for (i = 0; i < tlen-1; i++) {
    t[i] = t[i+1] - t[i];
  }
  printf("\n");
  printf("median        : %llu\n", median(t, tlen));
  printf("average       : %llu\n", average(t, tlen-1));
  if (mult > 1) {
    printf("median  (%3dx): %llu\n", mult, mult*median(t, tlen));
    printf("average (%3dx): %llu\n", mult, mult*average(t, tlen-1));
  }
  printf("\n");
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

static void Hdigest2(unsigned char* D,
	const unsigned char* pk, const unsigned char* R,
	const unsigned char* m, const unsigned int mlen)
{

	Keccak_HashInstance ctx;
	Keccak_HashInitialize_SHAKE256(&ctx);
	Keccak_HashUpdate(&ctx, pk, PK_BYTES * 8);
	Keccak_HashUpdate(&ctx, R, HASH_BYTES * 8);
	Keccak_HashUpdate(&ctx, m, mlen * 8);
	Keccak_HashFinal(&ctx, NULL);
	Keccak_HashSqueeze(&ctx, D, HASH_BYTES*8);
}

int main()
{
    unsigned long long t[NTESTS];

    unsigned char m[MLEN];
    unsigned char sm[MLEN+CRYPTO_BYTES];
    unsigned char m_out[MLEN+CRYPTO_BYTES];
	uint64_t shakestate[25] = { 0 };
    unsigned char out[SHAKE256_RATE];
	gf31 x1[N], x2[N], x3[M];
	signed char F[F_LEN];

    int i;

    randombytes(m, MLEN);

    printf("-- api --\n\n");

    for(i=0; i<NTESTS; i++) {
        t[i] = cpucycles();
		G(x3, x1, x2, F);
    }
    print_results("G: ", t, NTESTS, 1);

    for(i=0; i<NTESTS; i++) {
        t[i] = cpucycles();
		shake256_absorb(shakestate, out, 2 * HASH_BYTES);
		shake256_squeezeblocks(out, 1, shakestate);
    }
    print_results("shake_absorb: ", t, NTESTS, 1);

    for(i=0; i<NTESTS; i++) {
        t[i] = cpucycles();
		Keccak_HashInstance ctx;
		Keccak_HashInitialize_SHAKE256(&ctx);
		Keccak_HashUpdate(&ctx, out, 2*HASH_BYTES*8);
		Keccak_HashFinal(&ctx, NULL);
		Keccak_HashSqueeze(&ctx, out, SHAKE256_RATE*8);
    }
    print_results("shake_absorb2: ", t, NTESTS, 1);

    for(i=0; i<NTESTS; i++) {
        t[i] = cpucycles();
		Hdigest(m_out, sm, sm, m, MLEN);
    }
    print_results("Hdigest: ", t, NTESTS, 1);

    for(i=0; i<NTESTS; i++) {
        t[i] = cpucycles();
		Hdigest2(m_out, sm, sm, m, MLEN);
    }
    print_results("Hdigest2: ", t, NTESTS, 1);

	Hdigest2(m_out, sm, sm, m, MLEN);
	Hdigest2(out, sm, sm, m, MLEN);

    return 0;
}
