## MQDSS

The code in this branch of the repository corresponds to the [MQDSS submission](http://mqdss.org) to [NIST's Post-Quantum Cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Round-1-Submissions). It starts off from the code as submitted to NIST, and contains a few fixes for bugs that surfaced since then.


### Parameters

To switch between the MQDSS-48 and MQDSS-64 parameter sets, we adjust the relevant parameters in `params.h` accordingly. In particular, this concerns `M = N` and `ROUNDS`, as well as `SEED_BYTES` and `HASH_BYTES` (which should be set to `48`, `135`, `16` and `32` versus `64`, `202`, `24` and `48` for the respective parameter sets). The recommended parameter sets are predefined in the `params/` directory. These parameters are motivated in detail in [the specification document](http://mqdss.org/specification.html).

### Forgery Attack

From this implementation of MQDSS, we give a forgery attack that uses less than 2^k random oracle calls to forge a signature.

For testing, the number of rounds is reduced to 40. We also have added a new parameter called FIRST_ROUND_GUESSES specifying the number of repetitions to attack in the first phase, which is set to 11 for NUM_ROUNDS=40. (In practice, 12 leads to a slightly faster attack. This is discussed in the accompanying note.)

We added a test called `test_forge` in the test directory, which calls the forgery attack on the current parameter set. Once a forgery is found, it is verified using the unmodified verification code.

For the L1 parameter set with number of rounds reduced to 40, we expect the forgery to take about 10 minutes on a standard desktop PC, using the avx2 implementation. Note that we did not implement a variant that repeats the second phase if we run out of inputs.
This means that in some forgery attempts, the attack will not find a valid forgery. This event theoretically happens with a probability of 38 per cent and can be avoided as shown in the accompanying note.


### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication.
