// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file test_ed25519_contract.c
 * @brief eos's half of the Ed25519 contract shared with eBoot.
 *
 * eos and eBoot each carry their own Ed25519 verifier. They are different
 * implementations with opposite return conventions -- ed25519_verify() here
 * returns 1 to accept, eBoot's eos_ed25519_verify() returns EOS_OK -- doing the
 * same job on the same wire format. For a while only this side rejected
 * low-order public keys, and nothing in either repo could notice: there is no
 * shared build, and the two are far too different for a source diff to mean
 * anything.
 *
 * tests/vectors/ed25519_contract_vectors.h is the part that can be shared: pure
 * data, byte-identical in both repos, with a digest over it. Each side runs its
 * own verifier against every vector and prints that digest. A change to one copy
 * that does not reach the other shows up as two different digests.
 *
 * The eBoot-side twin is tests/unit/test_ed25519_contract.c in
 * embeddedos-org/eBoot. Both should always report the digest below.
 */

#include "ed25519.h"

#include "vectors/ed25519_contract_vectors.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned failed = 0, accepted = 0, refused = 0, positives = 0;
    int i;

    printf("Ed25519 contract vectors\n");
    printf("  digest: %s\n", EOS_ED25519_CONTRACT_DIGEST);
    printf("  count:  %d\n\n", EOS_ED25519_CONTRACT_COUNT);

    for (i = 0; i < EOS_ED25519_CONTRACT_COUNT; i++) {
        const eos_ed25519_contract_vector_t *v = &eos_ed25519_contract_vectors[i];

        /* eos convention: 1 accepts, 0 refuses -- the inverse of eBoot's. */
        int got_accept = (ed25519_verify(v->signature, v->message,
                                         v->message_len, v->public_key) == 1);

        if (got_accept) accepted++; else refused++;
        if (v->expect_accept) positives++;

        if (got_accept != v->expect_accept) {
            printf("  [FAIL] %s\n         expected %s, got %s\n         %s\n",
                   v->name,
                   v->expect_accept ? "ACCEPT" : "refuse",
                   got_accept ? "ACCEPT" : "refuse",
                   v->why);
            failed++;
        }
    }

    printf("  %u accepted, %u refused, %u wrong\n\n", accepted, refused, failed);

    if (failed) {
        printf("[FAIL] %u of %d contract vectors behaved incorrectly\n",
               failed, EOS_ED25519_CONTRACT_COUNT);
        return 1;
    }

    /* A verifier that refuses everything satisfies all 73 negative vectors, so
     * the three RFC 8032 signatures carry the whole weight of proving this
     * still accepts real ones. Fail loudly if they are ever dropped. */
    if (positives == 0) {
        printf("[FAIL] the corpus has no accept vectors; "
               "a verifier that refuses everything would pass\n");
        return 1;
    }

    printf("[PASS] all %d contract vectors behaved as specified (%u must accept)\n",
           EOS_ED25519_CONTRACT_COUNT, positives);
    return 0;
}
