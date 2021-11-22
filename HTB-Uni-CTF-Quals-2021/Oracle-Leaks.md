# Oracle Leaks

**Writeup by: ** arcayn
**Category: ** Crypto
**Difficulty: ** Medium

We are given a service, along with its python source code. The service gives us three options:
```
1. Get public key.
2. Get encrypted flag.
3. Get length.
```
We can see from the python source that a new RSA instance with a unique public/private keypair is generated on each connection, so whatever we do to decrypt the flag, we have to do in a single socket connection. Both options (1) and (2) are self-explanitory, so we'll focus on option (3). Investigating the source code, we see 
```python
print('Provide a ciphertext:\n'+\
			'> ')
ct = input()
ct = ct.encode()
pt = tmp.decrypt(ct)
length = get_length(pt)
print('Length: ' + str(length) + '\n')
```
And then `get_length` is given by:
```python
def get_length(pt):
	res = 0
	if (len(bin(pt)) - 2) % 8 != 0:
		res += 1
	res += (len(bin(pt)) - 2) // 8
	return res
```
We can see that this function will return the length, in bytes, of whatever number is given to it. Thus we can see that the `get_length` function will give us the byte length of the RSA decryption of any ciphertext we send it. We are therefore given access to an oracle which will potentially open the door for the very strong attack model of Adaptive Chosen-Ciphertext attacks (CCA2). 

The most famous CCA2 attack against RSA is [Bleichenbacher's attack](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf). In this case, we can use a padding oracle for PKCS padding to determine whether the most significant bytes of the result of an RSA decryption are `\0x00\0x02`, in which case we know that the decryption result is in the interval:
$$[2 \cdot 2^{k - 16}, 3 \cdot 2^{k - 16} - 1]$$
With $k$ the length in bits of the RSA modulus $N$. If we are allowed to make queries with whatever ciphertexts we choose (Chosen-Ciphertext) and then observe the result before we make the next query (Adaptive), then this oracle is enough to decrypt any arbitrary message encrypted by the public key corresponding to the oracle. We can slightly modify this attack. We define an oracle as follows:
```python
def oracle(w):
    conn.recvuntil(b'> ')
    conn.sendline(b'3')
    conn.recvuntil(b'> ')
    
    conn.sendline(hexlify(long_to_bytes(w)))
    a = conn.recvline()
	
    return int(a.split(b' ')[1][:-1].decode()) == 127

```
Where `conn` is a socket connection to the challenge server. Now note that if this oracle returns true, we know that the most significant byte of the decryption is `\0x00`, but the second most significant byte is nonzero. Thus our decryption lies in the interval:
$$[1 \cdot 2^{k - 16}, 256 \cdot 2^{k - 16} - 1]$$
We can thus modify Bleichenbacher's attack to work on this interval instead of the previous one, and decrypt the encrypted flag. This does in fact work and we were able to extract the flag from a local copy of the server in ~150k queries. However, there is a 300s timeout on socket connections to the remote challenge server, which means we must use a different, more efficient attack.

This is when my research led me to [Manger's attack](https://www.iacr.org/archive/crypto2001/21390229.pdf), a much less well known CCA2 attack against RSA. In this case, instead of an oracle which tells use whether the most significant bytes of the decryption are `\x00\x02`, it instead simply tells us whether the first byte is `\x00`.  We can trivially modify our oracle from before for this purpose:
```python
def oracle(w):
    conn.recvuntil(b'> ')
    conn.sendline(b'3')
    conn.recvuntil(b'> ')
    
    conn.sendline(hexlify(long_to_bytes(w)))
    a = conn.recvline()
	
    return int(a.split(b' ')[1][:-1].decode()) > 127

```
So it returns `True` for the first byte being nonzero and `False` for the first byte being zero. I used an implementation of Manger's attack from [GitHub](https://github.com/anderspkd/manger-cca-rsa-oaep-demo). The complete solve script was then:
```python
from requests import get as _get
from hashlib import sha1
import json
from math import log, floor
from Crypto.Util import number
from decimal import Decimal, getcontext, ROUND_CEILING, ROUND_FLOOR

import os
import random
import time
from collections import namedtuple
from binascii import unhexlify,hexlify
from pwnlib.tubes.remote import remote
from Crypto.Util.number import bytes_to_long,long_to_bytes

conn = remote('209.97.132.64', 31163)


# True  => (c^d mod n) >= B
# False => (c^d mod n) < B
def query_oracle(f):
    conn.recvuntil(b'> ')
    conn.sendline(b'3')
    conn.recvuntil(b'> ')
    
    
    h = pow(f, e, n)
    w = (h * ciphertext) % n

    conn.sendline(hexlify(long_to_bytes(w)))
    a = conn.recvline()
    return int(a.split(b' ')[1][:-1].decode()) > 127


def step1(c):
    f1 = 2
    while not query_oracle(f1):
        f1 = 2 * f1
    input("Proceed")
    return f1


def step2(c, f1):
    f2 = int(floor((n + B) / B) * (f1 / 2))
    while query_oracle(f2):
        f2 = int(f2 + (f1 / 2))
    input("Proceed")
    return f2


def step3(c, t2):

    # Helper
    def Dec(thing, rounding):
        if rounding == 'up':
            return Decimal(thing).to_integral_value(rounding=ROUND_CEILING)
        else:
            return Decimal(thing).to_integral_value(rounding=ROUND_FLOOR)
    getcontext().prec = 500

    m_min = Dec(n / t2, 'up')
    m_max = Dec((n + B) / t2, 'down')
    t_tmp = Dec((2 * B) / (m_max - m_min), 'down')
    i = Dec((t_tmp * m_min) / n, 'up')
    f3 = Dec((i * n) / m_min, 'up')

    while True:
        if not query_oracle(int(f3)):
            m_max = Dec((i*n + B) / f3, 'down')
        else:
            m_min = Dec((i*n + B) / f3, 'up')
        diff = Decimal(m_max - m_min)
        print(f'm_max - m_min: {diff}')
        if diff == 0:
            break
        t_tmp = Dec((2 * B) / (m_max - m_min), 'down')
        i = Dec((t_tmp * m_min) / n, 'up')
        f3 = Dec((i * n) / m_min, 'up')

    return m_min


if __name__ == '__main__':

    for _ in range(5):
        conn.recvline()
    conn.sendline(b'2')
    e = conn.recvline()
    print (e.split(b' ')[3][:-1])
    ciphertext = bytes_to_long(unhexlify(e.split(b' ')[3][:-1]))
    for _ in range(5):
        conn.recvline()
    conn.sendline(b'1')
    e = conn.recvline()
    print (e)
    n = int(e.split(b' ')[2].decode()[2:-2],16)
    e= int(e.split(b' ')[3].decode()[1:-3],16)
    print (hex(n),hex(e))
    input("Confirm correct")
    
    k = Decimal(str(log(n, 256))).to_integral_value(rounding=ROUND_CEILING)
    B = getcontext().power(Decimal(2), Decimal(8*(k-1)))

    assert 2*B < n, "Shouldn't happen"

    # (t1 / 2)*m \in [B/2, B)
    t1 = step1(ciphertext)

    # t2*m \in [n, n + B)
    t2 = step2(ciphertext, t1)

    m = int(step3(ciphertext, t2))
	print (long_to_bytes(m))
```
This attack requires far fewer queries than Bleichenbacher, and is able to complete in only a few minutes, so we get the flag as:

`HTB{m4ng3r5_4tt4ck_15_c001_4nd_und3rv4lu3d}`