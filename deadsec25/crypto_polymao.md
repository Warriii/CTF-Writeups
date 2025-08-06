## Polymao (1 Solve, 500 Pts)
```
A weird signature scheme?
```

We are given a massive dist that I will leave behind as a zip file and not in the writeup. But essentially, we have a copy of [PlonkPy](https://github.com/ETHorHIL/Plonk_Py), a python implementation of the zero knowledge PLONK protocol from [this paper](https://eprint.iacr.org/2019/953).

The high level overview is that Plonk allows one to encode a polynomial as a challenge, and one may submit a valid state of values that resolve the polynomial. This is a witness, and Plonk does fiat-shamir, pairings, and other things at the backend to turn it into a zero knowledge scheme.

One of the new files that we have access to is `server.py`

```py
import random
from ssbls12 import Fp, Poly, Group
from polynomial_evalrep import get_omega, polynomialsEvalRep
from setup import setup_algo
from verifier import verifier_algo
from circuit_setup import preprocess
from utils import *
import json
from ast import literal_eval

class PolySign:
    # Trusted setup
    def setup(self):
        print('Pls be patient...')
        message = input('Message: ')
        message = message.encode()
        if len(message) > 100 or len(message) < 3:
            print("Message too long or short")
            return

        wires, permutation, gates_matrix = preprocess(message)

        # Mundane stuff
        self.n = len(gates_matrix[0])
        n = self.n
        # seed = random.randint(0, entropy)
        message = list(message)

        L = list(range(len(message)))
        public_input = list(message)
        public_input = [Fp(x) for x in public_input]
        CRS, Qs, p_i_poly, perm_prep, verifier_prep = setup_algo(
            gates_matrix, permutation, L, public_input
        )
        self.perm_prep = perm_prep
        self.verifier_prep = verifier_prep

        res = json.dumps({
            'n': n,
            'perm_prep': [[repr(y) for y in x] if type(x) == list else repr(x) for x in perm_prep],
            'public_input': [int(x) for x in public_input],
            'CRS': [Group_to_hex(x) for x in CRS],
            'Qs': [repr(x) for x in Qs],
        })
        print('setup:', res)
        return res
        
    def verify_msg(self):
        signature = json.loads(input("Enter signature: "))
        msg, L, public_input, proof = (signature['msg'], signature['L'], signature['public_input'], signature['proof'])
        if len(msg) > 100 or len(msg) < 3:
            print("Too long or short")
            return
        
        msg = msg.encode()

        proof = literal_eval(proof)
        proof = convert_proof_elements(proof)
        assert all(x == y for x, y in zip(msg, public_input))

        # From setup.py
        n = self.n
        omega_base = get_omega(Fp, 2 ** 32, seed=0)
        omega = omega_base ** (2 ** 32 // n)
        omegas = [omega ** i for i in range(n)]
        PolyEvalRep = polynomialsEvalRep(Fp, omega, n)
        # The public input poly vanishes everywhere except for the position of the
        # public input gate where it evaluates to -(public_input)
        p_i = [Fp(0) for i in range(len(omegas))]
        for i, k in zip(L, public_input):
            p_i[i] = Fp(-k)
        p_i_poly = PolyEvalRep(omegas, p_i)
        

        verifier_algo(proof, n, p_i_poly, self.verifier_prep, self.perm_prep[2])

        print('Now you see me. Flag: DEAD{redact}')

ps = PolySign()
print("Welcome to PolySign!")
print("Create your NP signature!")

while True:
    ps.setup()
    ps.verify_msg()
```

Evidently, to derive the flag we must submit some bytes message, receive a challenge in the form of "setup" by the server, and then send a signature that describes a zero knowledge proof that we have a solution. Notably, we see

```py
wires, permutation, gates_matrix = preprocess(message)
```

and a look into Plonk, notably the ipynb tutorial given, tells us that:
- wires are essentially LHS, RHS, OUT in LHS OPERAND RHS EQUAL OUT
- gates_matrix tells us the OPERAND
- permutation encodes information telling us which wires lead into which

As a demonstration, suppose we want to encode the polynomial $x^3 + x + 5 = 35$

We rewrite the polynomial as:
```
x    * x = var1
var1 * x = var2  
var2 + x = var3  
       5 = 5    
      35 = 35    
var3 + 5 = 35   
```
Obtaining the following vectors:

`a` for the left operands:  `[x, var1, var2, 1, 1 var3]`  
`b` for the right operands :`[x, x, x, 5, 35, 5]`  
`c` for the results:       `[var1, var2, var3, 5, 35, 35]`  
`gates_matrix`  for the operations:   `[mul, mul, add, const, const, add]`

wires is `a + b + c` where `+` is list concatenation;

permutation tells us information that `wire_a[1] == var1 == wire_c[0]` and other wires that are equal to each other

gates_matrix contains operations `[mul, mul, add, const, const, add]` 

The wires and permutation forms our circuit in this scheme.

For the zero knowledge scheme to function, in essence:
- A known polynomial equation is provided and encoded in Plonk as a circuit
- A Prover, who knows the solution to the equation, parses his solution into the wires, evaluating what each wire value would contain after all the operations are done, saving this as a witness
- A Verifier, then plugs the witness into the polynomial equation / circuit, and ensures that it holds

In the backend, a bunch of fiat-shamir, elliptic curve pairings etc. are done to ensure it is secure. Except...this implementation has what we call a [Frozen Heart](https://blog.trailofbits.com/2022/04/15/the-frozen-heart-vulnerability-in-bulletproofs/) vulnerability. I myself am not familiar with zk-proofs, so in making this writeup I reached out to one of my all time zk-friends.

![alt text](images/image.png)

Coincidentally he had been playing in deadsec under another team, and from the deadsec discord's discussion and from DMing him there is a different, unintended vulnerability!

For time being, I've elected to set frozen heart for later and focus on the unintended. This arises by analysing the polynomial equation that is being encoded.

```py
def preprocess(msg):
    # Example usage:
    msg = list(msg) # convert from bytes
    n = proof_bits + 7  # For x_0, x_1, ..., x_n. Not len(gates_matrix[0])
    g = sum(msg) % P
    assert g % 2 == 1
    g_values = [pow(g, 2**i, P) for i in range(n + 1)] 
    # x_values = [1, 0, 1, 1, 0, 1] + [0]*(n + 1 - 6)  # Example x values (binary)

    circuit = gen_circuit(n, msg, g, g_values)

    wires = circuit['wires']['left'] + circuit['wires']['right'] + circuit['wires']['output']

    permutation = permute_idices(wires)

    return wires, permutation, circuit['gates']
```
Reverse engineering `preprocess()`, we see it takes a bytes message, then derives `g = sum(message)`, and sends $g, g^2, g^4, g^8, ... \quad (\bmod P)$ to `gen_circuit()`

```py
    # Public input
    for c in msg:
        wires['left'].append('1')
        wires['right'].append(str(c))
        wires['output'].append(str(c))
        gates_matrix.append(public_input)
     
    var_idx = 0

    # x values
    # for i in range(n + 1):
    #     vars[i] = x_values[i]
    var_idx += n + 1

    # x values are binary
    for i in range(n + 1):
        wires['left'].append(f'var{i}')
        wires['right'].append('-1')
        wires['output'].append(f'var{var_idx}')
        # vars[var_idx] = x_values[i] - 1
        gates_matrix.append(add)
        var_idx += 1
        wires['left'].append(f'var{var_idx - 1}')
        wires['right'].append(f'var{i}')
        wires['output'].append('0')
        gates_matrix.append(mul)

    # Calculate v_i = x_i * g_i + 1 - x_i = x_i*(g_i - 1) + 1
    v_wires = []
    for i in range(n + 1):
        # Multiplication gate: x_i * (g_i - 1)
        wires['left'].append(f'var{i}')
        wires['right'].append(str(g_values[i] - 1))  # Constant multiplication
        wires['output'].append(f'var{var_idx}')
        # vars[var_idx] = x_values[i] * (g_values[i] - 1)
        gates_matrix.append(mul)
        temp_wire = var_idx
        var_idx += 1
        
        # Addition gate: + 1
        wires['left'].append(f'var{temp_wire}')
        wires['right'].append('1')  # Constant addition
        wires['output'].append(f'var{var_idx}')
        # vars[var_idx] = vars[temp_wire] + 1
        gates_matrix.append(add)
        v_wires.append(var_idx)
        var_idx += 1
    
    # Now create multiplication tree to compute product of all v_i
    current_product_wires = v_wires.copy()
    
    while len(current_product_wires) > 1:
        new_product_wires = []
        for i in range(0, len(current_product_wires), 2):
            if i + 1 < len(current_product_wires):
                # Multiply two elements
                wires['left'].append(f'var{current_product_wires[i]}')
                wires['right'].append(f'var{current_product_wires[i+1]}')
                wires['output'].append(f'var{var_idx}')
                # vars[var_idx] = vars[current_product_wires[i]] * vars[current_product_wires[i+1]]
                gates_matrix.append(mul)
                new_product_wires.append(var_idx)
                var_idx += 1
            else:
                # Odd number of elements, carry forward the last one
                new_product_wires.append(current_product_wires[i])
        current_product_wires = new_product_wires

    # k*N
    wires['left'].append(f'var{var_idx}')
    # vars[var_idx] = k
    var_idx += 1
    wires['right'].append(str(P))
    wires['output'].append(f'var{var_idx}')
    # vars[var_idx] = k*P
    gates_matrix.append(mul)
    var_idx += 1

    # h  = Final product - k*p
    final_product_wire = current_product_wires[0]
    wires['left'].append(f'var{final_product_wire}')
    wires['right'].append(f'var{var_idx - 1}') 
    wires['output'].append(str(f'var{var_idx}'))
    # vars[var_idx] = vars[final_product_wire] - vars[var_idx - 1]
    gates_matrix.append(sub)
    var_h = var_idx
    var_idx += 1

    # k2 * 2^(proof_bits)
    wires['left'].append(f'var{var_idx}')
    wires['right'].append(str(2**proof_bits)) 
    # vars[var_idx] = k2
    var_idx += 1
    wires['output'].append(f'var{var_idx}')
    # vars[var_idx] = k2 * (2**proof_bits)
    gates_matrix.append(mul)
    var_idx += 1 

    # h - k2 * 2^(proof_bits) == 0
    wires['left'].append(f'var{var_h}')  # h
    wires['right'].append(f'var{var_idx - 1}')
    wires['output'].append('0')
    gates_matrix.append(sub)
```
`gen_circuit()` is a bit more complicated, but the idea is it takes an integer x as a 67-bit input, interprets it as a 67 `0/1` variables, then for every `x_i`, multiplies `v_i = x_i*(g_i - 1) + 1` to some product value.

Since `v_i == 1` when `x_i == 0` and `v_i == g_i` when `x_i == 1`, we notice that the final product value is basically $\prod (g^{(x_i * 2^i)} \bmod p)$. NOT to be confused with $g^x \bmod p$, as the final product is done over integers and not over modulo p.

It then computes $h = \prod (g^{(x_i * 2^i)} \bmod p) - k_0 * P - k_1 * 2^{60}$, and the polynomial equation returns True if this value is $0$. 

It's essentially trying to test that $(g^x \bmod p) \bmod 2^{60} == 0$, thus in order to find a possible root we have to set some value $k_1 * 2^{60}$ and solve the discrete log problem, which would be very inefficient and too time consuming for the CTF.

However, because they allow us to set $k_0, k_1$ in our witness, and in not ensuring that $\prod (g^{(x_i * 2^i)} \bmod p) - k_0 * P < P$, we can simply find any valid $(k_0, k_1)$ pair that equates to $\prod (g^{(x_i * 2^i)} \bmod p)$.

Suppose we set some $g, x$ values. We can derive $C = \prod (g^{(x_i * 2^i)} \bmod p)$

To find $k_0, k_1$ such that $k_0 * P + k_1 * 2^{60} = C$, we can run extended gcd to find integers $u, v$ such that $u * P + v * 2^{60} = 1$, because $P$ and $2^{60}$ are coprime.

We derive $k_0, k_1$ by multiplying $u, v$ with $C$. This allows us to create a valid witness, which we then use to generate a valid proof locally to send on the server. The server receives this valid proof, and as a result, outputs the flag!

This upsolve was not made possible without help from various members in the deadsecCTF discord server. Huge thanks to Quasar from Smiley/FMC who more or less explained everything in layman terms for me and mhdo for aiding with debugging my upsolve and providing the solve script which I later cleaned up and added $k_0, k_1$ generation code for this writeup.

`solve1.py`
```py
from time import time
from ssbls12 import Fp
from polynomial_evalrep import get_omega, polynomialsEvalRep
from setup import setup_algo, omega_base
from verifier import verifier_algo
from prover import prover_algo
from circuit_setup import preprocess
from utils import *
import json
from ast import literal_eval
from circuit_setup import preprocess
from pwn import remote
import numpy as np

class PolySign_altered:
    # Trusted setup
    def setup(self, message:str):
        print('Pls be patient...')
        message = message.encode()
        if len(message) > 100 or len(message) < 3:
            print("Message too long or short")
            return

        wires, permutation, gates_matrix = preprocess(message)

        # Mundane stuff
        self.n = len(gates_matrix[0])
        n = self.n
        # seed = random.randint(0, entropy)
        message = list(message)

        L = list(range(len(message)))
        public_input = list(message)
        public_input = [Fp(x) for x in public_input]
        CRS, Qs, p_i_poly, perm_prep, verifier_prep = setup_algo(
            gates_matrix, permutation, L, public_input
        )
        self.perm_prep = perm_prep
        self.verifier_prep = verifier_prep
        return (n, perm_prep, public_input, CRS, Qs)
        
    def verify_msg(self, msg:str, L, public_input, proof):
        if len(msg) > 100 or len(msg) < 3:
            print("Too long or short")
            return
        
        msg = msg.encode()

        proof = literal_eval(proof)
        proof = convert_proof_elements(proof)
        assert all(x == y for x, y in zip(msg, public_input))

        # From setup.py
        n = self.n
        omega_base = get_omega(Fp, 2 ** 32, seed=0)
        omega = omega_base ** (2 ** 32 // n)
        omegas = [omega ** i for i in range(n)]
        PolyEvalRep = polynomialsEvalRep(Fp, omega, n)
        # The public input poly vanishes everywhere except for the position of the
        # public input gate where it evaluates to -(public_input)
        p_i = [Fp(0) for i in range(len(omegas))]
        for i, k in zip(L, public_input):
            p_i[i] = Fp(-k)
        p_i_poly = PolyEvalRep(omegas, p_i)
        
        verifier_algo(proof, n, p_i_poly, self.verifier_prep, self.perm_prep[2])

        print('Now you see me. Flag: DEAD{redact}')

START = time()
message = b'helloworld!'
L = list(range(len(message)))
wires, permutation, gates_matrix = preprocess(message)
wire_len = len(wires) // 3

P = 141528306768650330822240853633706129757483856122032705239787104121712635648968054105923247863678392515560924452725039847310690005346202502323120546096317520792028956290235540662469845864261110405157081321203178742884080504319649527761728762230759915456400855499594340877712636427414085441127049782858937718299
g, x, proof_bits = sum(message), 123456, 60

# simulate circuit to derive its "g^x"
gx, i, x_ = 1, 0, x
while x_:
    if x_ & 1:
        gx *= pow(g, 2**i, P)
    x_ //= 2
    i += 1
assert gx % P == pow(g, x, P)

# solve k1, k2 s.t. "g^x" - k1 P - k2 2**proof_bits == 0
def gcdExtended(a, b): 
    if a == 0 : 
        return b,0,1
    gcd,x1,y1 = gcdExtended(b%a, a) 
    x = y1 - (b//a) * x1 
    y = x1 
    return gcd,x,y 

_, u, v = gcdExtended(P, 2**proof_bits)
k1 = u * gx
k2 = v * gx
assert gx - k1 * P - k2 * 2**proof_bits == 0
evaluate = f'var339={str(k1)}\nvar342={str(k2)}\n'
for i in range(68): # x vars in binary
    evaluate += f'var{i} = {(x >> i) & 1}\n'

ADD = np.array([1, 1, 0, -1, 0])
SUB = np.array([1, -1, 0, -1, 0])
MUL = np.array([0, 0, 1, -1, 0])
LEFT, RIGHT, OUT = wires[:wire_len], wires[wire_len:2*wire_len], wires[2*wire_len:]
for l, r , o, gate in zip(LEFT, RIGHT, OUT, gates_matrix.transpose()):
    if o.isdigit():
        continue
    if np.array_equal(gate, ADD):
        evaluate += f'{o} = {l} + {r}\n'
    if np.array_equal(gate, MUL):
        evaluate += f'{o} = {l} * {r}\n'
    if np.array_equal(gate, SUB):
        evaluate += f'{o} = {l} - {r}\n'
var_dict = {}
exec(evaluate, var_dict)
witness = [eval(i, var_dict) if i[:5] != 'empty' else 0 for i in wires]

(m, n) = gates_matrix.shape

assert n & n - 1 == 0, "n must be a power of 2"

# Derive p_i_poly following setup_algo()
omega = omega_base ** (2 ** 32 // n)
ROOTS = [omega ** i for i in range(n)]
PolyEvalRep = polynomialsEvalRep(Fp, omega, n)
public_input = [Fp(0) for _ in range(len(ROOTS))]
for i, k in zip(L, message):
    public_input[i] = Fp(-k)
p_i_poly = PolyEvalRep(ROOTS, public_input)

## LOCAL
# SERVER = PolySign_altered()
# n, perm_prep, public_input, CRS, Qs = SERVER.setup(message.decode())

## REMOTE
R = remote('nc.deadsec.quest', 32430)
print(R.recvline())
print(R.recvline())
print(R.recvline())
R.recvuntil(b'Message: ')
R.sendline(message)
print(R.recvline())
print(R.recvline())
print(R.recvline())
R.recvuntil(b'setup: ')
res = json.loads(R.recvline().rstrip().decode())
for i, dat in enumerate(res['perm_prep'][0]):
    res['perm_prep'][0][i] = Fp(int(dat))
for i, dat in enumerate(res['perm_prep'][1]):
    res['perm_prep'][1][i] = Fp(int(dat))
res['perm_prep'][2] = Fp(int(res['perm_prep'][2]))
for i, dat in enumerate(res['perm_prep'][3]):
    res['perm_prep'][3][i] = poly_from_str(dat)
for i, dat in enumerate(res['public_input']):
    res['public_input'][i] = int(dat)
for i, dat in enumerate(res['CRS']):
    res['CRS'][i] = Group_from_hex(dat)
for i, dat in enumerate(res['Qs']):
    res['Qs'][i] = poly_from_str(dat)
CRS, Qs, perm_prep = res['CRS'], res['Qs'], res['perm_prep']

# Generate valid proof locally
proof_SNARK, u = prover_algo(witness, CRS, Qs, p_i_poly, perm_prep)

## LOCAL
# SERVER.verify_msg(message.decode(), L, public_input, str(proof_SNARK))

## REMOTE
signature = {}
signature['msg'] = message.decode()
signature['public_input'] = list(message)
signature['L'] = L
signature['proof'] = str(proof_SNARK)
R.recvuntil(b'Enter signature:')
R.sendline(json.dumps(signature).encode())
R.interactive()
print(f"Time taken: {round(time() - START, 2)} seconds")

"""
[x] Opening connection to nc.deadsec.quest on port 32430
[x] Opening connection to nc.deadsec.quest on port 32430: Trying 34.59.29.150
[+] Opening connection to nc.deadsec.quest on port 32430: Done
b'Welcome to PolySign!\n'
b'Create your NP signature!\n'
b'Pls be patient...\n'
b'Starting Setup Phase...\n'
b'Starting Verifier Preprocessing...\n'
b'Setup Phase Finished!\n'
Starting the Prover Algorithm
Starting Round 1...
Round 1 Finished with output:  [(28256723295194272838330852776014938597922546180890465756815318593251296052280975260004685261301248588114111083570513, (21494725316249321179075912049147707733734481468299926110933770547943379176499329797950234665257352860979257881256344, 341466506927813820191145022590360927758143354557441623265716374152824720852311382151682606440193299036883318842585)), (22616267929864807465837984081524410464177132120504862677670766985346615354756943305063132711861215067945221177687621, (19772441083815050009369976333598347295201202992719528575092141483950912193963021960172436801231213771450500071916102, 2945420003133079218917809774428657113798913209600981844281142332432082377587109189611239319164492899763194416250132)), (23234464662904285026115784541164979468801799312246896092790226313417158191385044957062176508391157629814566952122907, (24829004809664636936781251213332445890863687749445905803579485803607291540205793478556858886603877790178327529408429, 3732027868346098827977254096543581727898142830339787105610736370022131532073937132151731296478720974487448572976110))]
Starting Round 2...
Round 2 Finished with output:  (26547358818408463085515383428689086220965801848359065922541171657528094373241492618223831117355559140590381784096971, (23011363811941851696881208962129308672173457052849284858146081547254079392222553904769724977240263615851322447511270, 717560159128974577979153394738703468693465208068757595134745427007340360845267047447535211400252776524384641315946))
Starting Round 3...
Round 3 Finished with output:  [(20111446809421769963647730835472166358310683192926537905793768599057798679537135368919971643356329066470802129671782, (26330640232205184441383681434454127914635845092326456446340442334414896619675926633740618360063774222853326702749704, 1051444453553113612009814099457749206013562633105616743125571467428268568767703273163996230480187675561161135841785)), (21588809159917966853777643711033679048002814256160018733975506147768185145942290446683980988258086800529249736000959, (23094114395679515334261305665955687206616287486966663710053835237401095484412906281813262829247152806352679808250639, 1351715290936462418269166466799236294913690933913977264521032968623549411458005091011711050460243717429243725103552)), (22858308770834493405670342539906808164861702228946092155675112234698290419913242840512995315402027099034176603848517, (22197580466855284433307387962348302985184312030518438186140037236582139826308266114017647781964231846713307332967479, 3603989019227856060131489670648977287494891547133770044537287278873157935886773890960280156991829505078964480917144))]
Starting Round 4...
Round 4 Finished with output:  [41844890573693482949174417406617523925910014778199798395578030114215547019176, 1733974407228387602124897262307482528582525932322024488142171070955279743079, 20467786961824264301566076854041712914752198096314706931775386638080845624636, 35602953356586795515094939194000092995551519392036882264027655616323548072967, 47116009883461531453799254809778510098742320143797694012605154265042553986841, 6272800430486130533552078805716527705243436081104712103451108616313480300756, 12132748415963135357961095077356266026635067869183893656733139060604057367768, 35287236289123071786204858064514482168932369976456012996895256724938337707086]
Starting Round 5...
Round 5 Finished with output:  [(25396940053984546623105474644906509233703474086984776694738222851697824857353254147757010799896415449004370892089553, (20478373648259429092097277566107027953965507544318653176868543087194332670505786057315991000854997547078027635649201, 2782409635804684292032950694030354158099515283939987560378119275804843353339732981146420490092407030836255715992401)), (20957032311931271445905263837599789061261316110460997586243072748441274907540074785037176840687788103444837522864576, (24666116715811903440317251507187440586734394648515512003437039158657387697025197025930835457588409510312015411191179, 134066584734811122357533945115400906404221930030025159597542541146273025697007329333106480098907317931663922968988))]
[*] Switching to interactive mode
 Starting Verification...
Check1: Elements in group?
Check2: Elements in field?
Check3: Public input in field?
<class 'polynomial_evalrep.polynomialsEvalRep.<locals>.PolynomialEvalRep'>
Step4: Recompute challenges from transcript
Step5: Evaluate vanishing polynomial at zeta
Step6: Evaluate lagrange polynomial at zeta
Step7: Evaluate public input polynomial at zeta
Step8: Compute quotient polynomial evaluation
Step9: Comupte first part of batched polynomial commitment
Step10: Compute full batched polynomial commitment
Step 11: Compute group encoded batch evaluation
Check12: Batch validate all evaluations via pairing
Verification Successful!
Now you see me. Flag:
DEAD{w43k_fiat_sh4m1r_ru1ns_3veryth1ng_bd85e444ed358ae3}
Pls be patient...
Message: [*] Interrupted
Time taken: 783.33 seconds
[*] Closed connection to nc.deadsec.quest port 32430
"""
```

The second, and intended vulnerability, was to leverage