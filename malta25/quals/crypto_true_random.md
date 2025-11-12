![image](Images/truerandom.png)

`chall.py`
```py
from qiskit.circuit.random import random_circuit
from qiskit.quantum_info import Operator
from qiskit.quantum_info import Statevector
from numpy import array, save
from math import log2
import random
random = random.SystemRandom()
flag = open("flag.txt", "r").read().strip()
flag_len = len(flag)*8
assert flag_len == 256
depth = 10
qubits = int(log2(flag_len))

flag_bits = [int(bit) for bit in ''.join(format(ord(c), '08b') for c in flag)]



def random_pair(op):
    otp_key = [random.choice([0,1]) for _ in range(flag_len)]
    i = Statevector(otp_key)
    f = i.evolve(op)
    enc = array([flag_bits[i] ^ otp_key[i] for i in range(flag_len)])
    return array([enc, f.data])

ops = []
for _ in range(13):
    qc = random_circuit(qubits, depth, measure=False)
    op = Operator(qc)
    ops.append(op)

sets = 256
data = array([random_pair(random.choice(ops)) for _ in range(sets)])
save("enc.npy", data)
```

`enc.npy`
```
See enc.npy in the same folder as this writeup.
```


A [Qiskit](https://www.ibm.com/quantum/qiskit) challenge! We see a 32-byte flag and 8 qubits being used. The qubits are used in 13 random quantum circuits involving them of depth 10. Over 256 "sets", a random circuit is used on a completely random one time 256-bit key. The output of the circuit alongside the flag bits xored with the input circuit bits is given.

While the use of a quantum circuit does obfuscate the otp bits per set, parsing it through a circuit is equivalent to a multiplication of some quantum state vector (we can visualise this as a vector of items in $\mathbb{C}$) by some [unitary matrix](https://en.wikipedia.org/wiki/Unitary_matrix) $U$.

A key property of a unitary matrix is that it is an [isometry](https://en.wikipedia.org/wiki/Isometry) with respect to the usual norm. That is, the norm of the vector $v$ is same as that of $U*v$, which is what the quantum circuit operator is doing to our otp vector. Thus, we can compute the vector norm of $F_i(\text{otp-vec})$ where $F_i$ is one of the 13 quantum circuit operations and $\text{otp-vec}$ is the otp key as a vector (that is, of form $ \lbrace 0/1 + 0*j \rbrace$). We notice the norm of our otp vector, $||\text{otp-vec}||$,  is simply the number of 1s in it, so $||F_i(\text{otp-vec})||$ gives us just that.

But how does this help?

We notice that the flag vector has 256 values. The otp key has 256 values, xored is the operation used, and we are given 256 sets of flag vector xored with the otp key value. This reeks of some kind of linearity matrix multiplication. Perhaps this is where the sum of the 1s in $\text{otp-vec}$ come in.

The standard matrix multiplication involves taking two vectors, multiplying them together in a hadamard product like way, then summing them into a value. If computing the norm gives us the sum, then perhaps the xor operation can be represented as a multiplication operation.

We know the xor truth table to be
```
A   B   A^B
0   0   0
0   1   1
1   0   1
1   1   1
```
Now, if we map the 0s to 1s and 1s to -1s, we get
```
 A'  B'  A'*B'
 1   1   1
 1  -1  -1 
-1   1  -1
-1  -1   1
```
Importantly, we see that the identity value, 1, is preserved; 1 * 1 = 1. If we had mapped 0s to -1s and 1s to 1s, then we have -1 * -1 = 1, which doesnt meet xor's 0 ^ 0 = 0.

Let this new mapping be represented as $H()$.

Then, when we let $F$ denote our 0/1 flag vector, and $O_i$ denote the $i$ th $\text{otp-vec}$, we have:

$F \oplus O_i \rightarrow H(F) * H(O_i)$

By xorring the LHS with $F$ again, we derive 

$H(O_i) = H(F) * H(F) * H(O_i) = H(F) * H(F \oplus O_i)$

To perform $\text{sum}(H(O_i))$, as $||O_i||$ gives us the number of 1s in $O_i$ (i.e. number of -1s in $H(O_i)$), $\text{sum}(H(O_i)) = -||O_i|| + (256 - ||O_i||) = 256 - 2 * || O_i ||$.

Now, because we are given $F \oplus O_i$, we can recover $H(F \oplus O_i)$. By letting this be the rows of our matrix $M$, we thus have 

$M * \text{column-vec}(H(F)) = \lbrace H(O_0), H(O_1), ..., H(O_255)\rbrace$

We can then solve for $H(F)$ with standard matrix solving, and then convert back to obtain the flag.

`solve.py`
```py
from sage.all import Matrix, vector
import numpy as np

enc = np.load('enc.npy')
M, v = [], []
for d0, d1 in enc:
    M.append([-1 if i == 1 else 1 for i in d0])
    v.append(256 - 2*round(np.linalg.norm(d1)**2))
M, v = Matrix(M), vector(v)
flag_vec = ["1" if i == -1 else "0" for i in M.solve_right(v)]
print(int("".join(flag_vec), 2).to_bytes(32, "big"))
# b'maltactf{f55dc5132f9529106d6e:3}'
```