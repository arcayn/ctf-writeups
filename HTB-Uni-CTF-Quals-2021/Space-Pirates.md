# Space Pirates

**Writeup by: ** arcayn
**Category: ** Crypto
**Difficulty: ** Easy

We are given a python script and some output, let's analyse these. The script appears to be creating an instance of the [Shamir Secret Sharing scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).  Looking at `msg.enc`, we see it is a dumped output from the program's `main()` function.
```python
sss = Shamir(92434467187580489687, 10, 18)
sss.create_pol()
share = sss.get_share()
seed(sss.secret)
key = randbytes(16)
cipher = AES.new(key, AES.MODE_ECB)
enc_FLAG = cipher.encrypt(pad(FLAG,16)).hex()
```
We can see that all the program does is create an instance of the scheme with 
```
p = 92434467187580489687
k = 10
n = 18
```
Then uses this instance's randomly generated secret to encrypt the flag. Let's now analyse the data we're given:
```python
f.write('share: ' + str(share) + '\n')
f.write('coefficient: ' + str(sss.coeffs[1]) + '\n')
f.write('secret message: ' + str(enc_FLAG) + '\n')
```
We are given the encrypted flag of course, as well as a single share. Now this single share should not be enough to deduce the secret, since the $k$ of this scheme is set to 10 - but let's investigate what this other piece of information we are given tells us. When initialising the scheme, a polynomial is generated using 
```python
def calc_coeffs(self):
        for i in range(1,self.n+1):
            self.coeffs.append(self.next_coeff(self.coeffs[i-1]))
```
Which clearly just appends $n$ coefficients to `self.coeffs`. Investigating `next_coeff`, we find:
```python
def next_coeff(self, val):
	return int(md5(val.to_bytes(32, byteorder="big")).hexdigest(),16)
```
This is a very important detail. We see that the next coefficient is uniquely determined by the previous one. So since we know `coeffs[1]` (as it is given to us), we immediately know every coefficient other than `coeffs[0]` - which is the secret - simply by iterating this function. Now finding the secret is trivial. We can represent the polynomial of this scheme as:
$$ f(x) = f'(x) + k $$
Where $k$ is the secret, and
$$ f'(x) = a_1 \cdot x^1 + ... + a_n \cdot x^n $$
Now note that we completely know $f'(x)$, and we can caluclate
$$ k = f(x) - f'(x) $$
If we are given a pair $(x, f(x))$. Now the share we are given is simply $(x_0, f(x_0))$, so we subsitute as above and obtain the secret, using this to decrypt the flag. The solve script is given by:

```python
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from random import randint, randbytes, seed

def calc_y(coeffs, x):
    y = 0
    for i, coeff in enumerate(coeffs):        
        y += coeff * pow(x, i+1)
    return y

def next_coeff(val):
        return int(md5(val.to_bytes(32, byteorder="big")).hexdigest(),16)


n = 18
k = 10
p = 92434467187580489687
coefficient = 93526756371754197321930622219489764824
x_0 = 21202245407317581090
y_0 = 11086299714260406068
enc_FLAG = b"1aaad05f3f187bcbb3fb5c9e233ea339082062fc10a59604d96bcc38d0af92cd842ad7301b5b72bd5378265dae0bc1c1e9f09a90c97b35cfadbcfe259021ce495e9b91d29f563ae7d49b66296f15e7999c9e547fac6f1a2ee682579143da511475ea791d24b5df6affb33147d57718eaa5b1b578230d97f395c458fc2c9c36525db1ba7b1097ad8f5df079994b383b32695ed9a372ea9a0eb1c6c18b3d3d43bd2db598667ef4f80845424d6c75abc88b59ef7c119d505cd696ed01c65f374a0df3f331d7347052faab63f76f587400b6a6f8b718df1db9cebe46a4ec6529bc226627d39baca7716a4c11be6f884c371b08d87c9e432af58c030382b737b9bb63045268a18455b9f1c4011a984a818a5427231320ee7eca39bdfe175333341b7c"

    
coeffs = [coefficient]
for x in range(0, k - 2):
    coeffs.append(next_coeff(coeffs[-1]))


f_prime_x_0 = calc_y(coeffs, x_0) % p
secret = (y_0 - f_prime_x_0) % p

seed(secret)
key = randbytes(16)
cipher = AES.new(key, AES.MODE_ECB)
from binascii import unhexlify
cthex = unhexlify(enc_FLAG)
dec_FLAG = unpad(cipher.decrypt(cthex), 16)
print (dec_FLAG)
```
And we get the flag as:

`HTB{1_d1dnt_kn0w_0n3_sh4r3_w45_3n0u9h!1337}`