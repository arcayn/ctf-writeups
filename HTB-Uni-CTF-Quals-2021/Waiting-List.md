# Waiting List
**Writeup by: ** arcayn
**Category: ** Crypto
**Difficulty: ** Hard

We are given a service to connect to and its python source. Investigating the file, we see that it initialises a signature scheme called `ECDSA`, and calls the `verify` method on whatever data we send over the connection.
```python
def verify(self, pt, sig_r, sig_s):
	h = sha1(pt).digest()
	h = bytes_to_long(h)
	h = bin(h)[2:]
	h = int(h[:len(bin(self.n)[2:])], 2)
	sig_r = int(sig_r, 16)
	sig_s = int(sig_s, 16)
	c = inverse(sig_s, self.n)
	k = (c *(h +self.key*sig_r)) %self.n
	if sig_r== pow(self.g,k,self.n ):
		if pt ==b'william;yarmouth;22-11-2021;09:00':
			return 'Your appointment has been confirmed, congratulations!\n' +\
				'Here is your flag: ' + FLAG
		else:
			return 'Your appointment has been confirmed!\n'
	else:
		return 'Signature is not valid\n'
```
We can see that this method does some preprocessing, creating an $n$-bit hash from `pt`, stored as $h$. $r$ and $s$ are then converted to integrrs, and we define
$$ c = s^{-1} \pmod(n) $$
Then we calculate
$$ k = c(h + xr) \pmod(n) $$
Where we define $x$ to be `self.key`. We then check that
$$ r = g^k \pmod(n) $$
If the signature $(r,s)$ is valid and the data is `william;yarmouth;22-11-2021;09:00`, we are rewarded with a flag. Thus we need to be able to generate a signature which passes this validation check for this data (referred to as $m$). Let's analyse the signing function then:
```python
def sign(self, pt):
		h = sha1(pt).digest()
		h = bytes_to_long(h)
		h = bin(h)[2:]
		h = int(h[:len(bin(self.n)[2:])], 2)
		self.k = randint(1, self.n-1)
		r = pow(self.g, self.k, self.n)
		s = (pow(self.k, -1, self.n) * (h + self.key * r)) % self.n
		lsb = self.k % (2 ** 7)
		return {"h": hex(h)[2:], "r": hex(r)[2:], "s": hex(s)[2:], "lsb": bin(lsb)[2:] }
```
Now the same preprocessing is done on the message to generate $h$, and $k$ is chosen randomly. We calculate:
$$ r = g^k \pmod(n) $$
$$ s = k^{-1}(h + xr) \pmod(n) $$
It's now obvious that this is a simple implementation of the Digital Signature Algorithm (despite the class name implying it is the elliptic-curve variant). We can verify that the verify function does indeed validate signatures of this form. This algorithm is cryptographically strong and is not an attack surface. However, the `sign` function also returns the 7 least significant bits of $k$. This exposes the scheme to a nonce-leakage attack.

We now look to the other files we are given. Specifically, `signatures.txt` provides the output of the signature routine for 200 pieces of data. This is more than enough to leverage the [Howgrave-Graham and Smart attack](https://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf) based on the LLL Lattice reduction algorithm. We use the implementation of this attack on ECDSA available [here](https://github.com/bitlogik/lattice-attack), and modify it to work with the standard DSA. The entire attack process is mostly the same, since the attack works against all DSA variants and computation is done in the general language of abelian groups. The only major change is in verifying which candidate private key is the correct one, since the public key is not made accessible by the service, so we instead check validity by ensuring that the key correctly verifies all the provided signatures. The final key-extraction script is given by:

```python
import random
from fpylll import LLL, BKZ, IntegerMatrix
from Crypto.Util.number import inverse as inverse_mod

NN = 115792089210356248762697446949407573529996955224135760342422259061068512044369

def verify(h, r, s, x):
        c = inverse_mod(s, NN)
        k = (c *(h + x*r)) % NN
        
        if r == pow(5,k,NN):
            return True
        return False

def reduce_lattice(lattice, block_size=None):
    if block_size is None:
        print("LLL reduction")
        return LLL.reduction(lattice)
    print(f"BKZ reduction : block size = {block_size}")
    return BKZ.reduction(
        lattice,
        BKZ.Param(
            block_size=block_size,
            strategies=BKZ.DEFAULT_STRATEGY,
            auto_abort=True,
        ),
    )

def verify_all(sigs,x):
    for s in sigs:
        if not verify(s["hash"], s["r"], s["s"],x):
            return False
    return True

def test_result(mat, sigdat):
    mod_n = NN
    for row in mat:
        candidate = row[-2] % mod_n
        if candidate > 0:
            cand1 = candidate
            cand2 = mod_n - candidate
            if verify_all(sigdat,cand1):
                return cand1
            if verify_all(sigdat,cand2):
                return cand2
    return 0


def build_matrix(sigs, num_bits, bits_type, hash_val):
    num_sigs = len(sigs)
    n_order = NN
    curve_card = NN
    lattice = IntegerMatrix(num_sigs + 2, num_sigs + 2)
    kbi = 2 ** num_bits
    inv = inverse_mod
    if hash_val is not None:
        hash_i = hash_val
    if bits_type == "LSB":
        for i in range(num_sigs):
            lattice[i, i] = 2 * kbi * n_order
            if hash_val is None:
                hash_i = sigs[i]["hash"]
            lattice[num_sigs, i] = (
                2
                * kbi
                * (
                    inv(kbi, n_order)
                    * (sigs[i]["r"] * inv(sigs[i]["s"], n_order))
                    % n_order
                )
            )
            lattice[num_sigs + 1, i] = (
                2
                * kbi
                * (
                    inv(kbi, n_order)
                    * (sigs[i]["kp"] - hash_i * inv(sigs[i]["s"], n_order))
                    % n_order
                )
                + n_order
            )
    else:
        # MSB
        for i in range(num_sigs):
            lattice[i, i] = 2 * kbi * n_order
            if hash_val is None:
                hash_i = sigs[i]["hash"]
            lattice[num_sigs, i] = (
                2 * kbi * ((sigs[i]["r"] * inv(sigs[i]["s"], n_order)) % n_order)
            )
            lattice[num_sigs + 1, i] = (
                2
                * kbi
                * (
                    sigs[i]["kp"] * (curve_card // kbi)
                    - hash_i * inv(sigs[i]["s"], n_order)
                )
                + n_order
            )
    lattice[num_sigs, num_sigs] = 1
    lattice[num_sigs + 1, num_sigs + 1] = n_order
    return lattice


MINIMUM_BITS = 4
RECOVERY_SEQUENCE = [None, 15, 25, 40, 50, 60]
SIGNATURES_NUMBER_MARGIN = 1.03


def minimum_sigs_required(num_bits):
    curve_size = len(bin(NN)) - 1
    return int(SIGNATURES_NUMBER_MARGIN * 4 / 3 * curve_size / num_bits)


def recover_private_key(
    signatures_data, h_int, bits_type, num_bits, loop
):

    # Is known bits > 4 ?
    # Change to 5 for 384 and 8 for 521 ?
    if num_bits < MINIMUM_BITS:
        print(
            "This script requires fixed known bits per signature, "
            f"and at least {MINIMUM_BITS}"
        )
        return False

    # Is there enough signatures ?
    n_sigs = minimum_sigs_required(num_bits)
    if n_sigs > len(signatures_data):
        print("Not enough signatures")
        return False

    loop_var = True
    while loop_var:
        sigs_data = random.sample(signatures_data, n_sigs)

        print("Constructing matrix")
        lattice = build_matrix(sigs_data, num_bits, bits_type, h_int)

        print("Solving matrix ...")
        for effort in RECOVERY_SEQUENCE:
            lattice = reduce_lattice(lattice, effort)
            res = test_result(lattice, sigdat)
            if res:
                return res
        loop_var = loop
        if loop:
            print("One more try")

    return 0

sd = ""
with open("signatures.txt") as f:
    sd = f.read()
sigdat = []
for l in sd.split("\n"):
    toks = l.split(";")
    try:
        sigdat.append({
            "hash": int(toks[0],16),
            "r": int(toks[1],16),
            "s": int(toks[2],16),
            "kp": int(toks[3],2)
        })
    except:
        continue

print (recover_private_key(sigdat, None, "LSB", 7, True))
```
Now it is simply a case of setting `self.key` in `challenge.py`  to
```
28087271824264061637232323229172283884798675032610970264493593070129563321986
```
as found by the script, and calling `sign` on `m` to obtain the signature we want. This yields
```
{"h": "ec3f8320a474fb62273546527057d734691d224b", "r": "f01445e1b327a9fee6c755743382e9c5671c2ac644b84e4662b4d3abae4a3283", "s": "dd0422f1e0107fbe86403c948f8c979480e68af3e0e44b6af5b4d41dc36bf946", "lsb": "1011001", "pt": "william;yarmouth;22-11-2021;09:00"}
```
We now just connect to the service, send this data, and collect the flag as:

`HTB{t3ll_m3_y0ur_s3cr37_w17h0u7_t3ll1n9_m3_y0ur_s3cr37_15bf7w}`
