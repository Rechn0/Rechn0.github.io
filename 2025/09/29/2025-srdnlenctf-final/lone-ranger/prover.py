from field import Fr, Polynomial
from ecc import r, G1, G2
from kzg import KZG
from transcript import Transcript
from Crypto.Cipher import AES
import os, json

# https://decentralizedthoughts.github.io/2020-03-03-range-proofs-from-polynomial-commitments-reexplained/

n = 8
assert n > 0 and n & (n - 1) == 0, "n must be a power of 2"
omega = Fr.multiplicative_generator()**((r - 1) // n)
H = [omega**i for i in range(n)]
X = Polynomial([0, 1])  # X
Z_H = Polynomial([-1] + [0] * (n - 1) + [1])  # X^n - 1

kzg = KZG(2 * n + 1)

key_len = 16
key = os.urandom(key_len)

proofs = []
for i in range(key_len):
    transcript = Transcript("lone-ranger", separator=f"<{i:02x}>")
    z = key[i]

    # Obtain a random polynomial f of degree n-1 with f(1) = z
    f = Polynomial.random_element(n - 1)
    f -= f(1) - z
    assert f(1) == z
    # Commit to the polynomial f
    f_cm = kzg.commit(f)
    transcript.append("f_cm", f_cm)

    # Compute the range polynomial
    g_evals = [z >> j for j in range(n)]
    g = Polynomial.from_ntt(g_evals)
    # Add zero-knowledge to the range polynomial
    alpha, beta = Fr.random_element(), Fr.random_element()
    g += (alpha * X + beta) * Z_H
    # Check that the evaluations of g in H are as expected
    for j in range(n):
        assert g(H[j]) == z >> j
    # Commit to the range polynomial
    g_cm = kzg.commit(g)
    transcript.append("g_cm", g_cm)

    # Obtain the batch scalar combinator tau
    tau = Fr(transcript.challenge())
    transcript.append("tau", tau)

    # Precompute g(omega * X)
    g_evals = g.to_ntt(n=2 * n)  # extend to 2n evaluations since g now has degree n+1 due to zk
    # Shift by 2 the evaluations to compute g(omega * X)
    g_omega = Polynomial.from_ntt(g_evals[2:] + g_evals[:2])
    # Check that the evaluations of g_omega are as expected
    x = Fr.random_element()
    assert g_omega(x) == g(omega * x)

    # Compute the check polynomials
    w1 = (g - f) * Z_H // (X - 1)
    w2 = g * (1 - g) * Z_H // (X - H[n - 1])
    w3 = (g - 2 * g_omega) * (1 - g + 2 * g_omega) * (X - H[n - 1])
    # Compute the quotient polynomial
    q = (w1 + tau * w2 + tau**2 * w3) // Z_H
    assert w1 + tau * w2 + tau**2 * w3 == q * Z_H, "some wj is not divisible by Z_H"
    # Commit to the quotient polynomial
    q_cm = kzg.commit(q)
    transcript.append("q_cm", q_cm)

    # Obtain the evaluation challenge rho
    rho = Fr(transcript.challenge())
    assert rho not in H, "rho must not be in H"
    transcript.append("rho", rho)

    # Compute the KZG openings
    g_rho, g_rho_cm = kzg.open(g, rho)
    g_omega_rho, g_omega_rho_cm = kzg.open(g, omega * rho)
    w_hat = f * Z_H(rho) // (rho - 1) + q * Z_H(rho)
    w_hat_rho, w_hat_rho_cm = kzg.open(w_hat, rho)

    # Construct the range proof, use G1.from_repr to parse the commitments
    proof = {
        "f_cm": repr(f_cm),
        "g_cm": repr(g_cm),
        "q_cm": repr(q_cm),
        "kzg_openings": {
            "g_rho": (int(g_rho), repr(g_rho_cm)),
            "g_omega_rho": (int(g_omega_rho), repr(g_omega_rho_cm)),
            "w_hat_rho": (int(w_hat_rho), repr(w_hat_rho_cm)),
        },
    }
    proofs.append(proof)

flag = os.getenv("FLAG", "srdnlen{this_is_a_fake_flag}").encode()
cipher = AES.new(key, AES.MODE_CTR)
flag_enc = cipher.encrypt(flag)

with open("output.json", "w") as f:
    json.dump({
        "proofs": proofs,
        "flag_enc": flag_enc.hex(),
        "nonce": cipher.nonce.hex(),
    }, f, indent=4)
