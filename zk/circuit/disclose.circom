pragma circom 2.1.0;

// Selective disclosure of a signed attribute vector.
// The issuer signs Poseidon(Poseidon(a[0..15]), a[16..19]) with EdDSA-Poseidon
// on Baby Jubjub.  The prover reveals a[i] where mask[i] = 1 and zero elsewhere,
// and binds the proof to a verifier nonce through a public input.
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";

template Disclose(N) {
    signal input attr[N];          // private
    signal input R8x;              // private signature
    signal input R8y;
    signal input S;
    signal input Ax;               // public issuer key
    signal input Ay;
    signal input mask[N];          // public disclosure mask
    signal input nonce;            // public verifier nonce
    signal output disclosed[N];

    component h1 = Poseidon(16);
    for (var i = 0; i < 16; i++) h1.inputs[i] <== attr[i];
    component h2 = Poseidon(N - 16 + 1);
    h2.inputs[0] <== h1.out;
    for (var i = 16; i < N; i++) h2.inputs[i - 15] <== attr[i];

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S <== S;
    sig.M <== h2.out;

    for (var i = 0; i < N; i++) {
        mask[i] * (mask[i] - 1) === 0;
        disclosed[i] <== attr[i] * mask[i];
    }
    signal nonceSq <== nonce * nonce;
}

component main {public [Ax, Ay, mask, nonce]} = Disclose(20);
