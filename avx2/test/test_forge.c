#include <stdio.h>
#include <string.h>
#include "../randombytes.h"
#include "../api.h"
#include "../params.h"

#define MLEN 32

int main()
{
    unsigned char pk[PK_BYTES];
    unsigned char sk[SK_BYTES];
    unsigned char m[MLEN];
    unsigned char sm[SIG_LEN + MLEN];
    size_t smlen;

    printf("Testing forgery for round reduced version (R=%d)...\n", ROUNDS);
    fflush(stdout);

    crypto_sign_keypair(pk, sk);
    randombytes(m, MLEN);
    return crypto_sign_forge(sm, &smlen, m, MLEN, pk);
}
