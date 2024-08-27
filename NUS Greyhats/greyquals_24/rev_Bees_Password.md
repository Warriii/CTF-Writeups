## Bee's Password (24 Solves, 810 Pts)

We're given a link to a drive containing 3 files.

`encrypted_password.txt`
```
gymzjsyaoxhq}dfp~hfhqzgxnc}bhtd~crnwbxqf~tnfmbpt|sznsgmggdhu__g{zsylrd_zyc^coroisfh_^ar~dllvh~hkcqbcg}ma|^ucl{c{^vle}z^_kdjy{{yoavrgrdkagzwdm}{~mblp|qgpmkjlwbcamsnws^qkupbrskespuh{yiul}gj|ss~resmgsbev~wbz^qvrzvfaiebfspigahf^mwv}joz~~tndzu`e}zw{mgsu`dr~tg~lt{aybm~~sjrliw^p~axh^kck|qs_}^b||qurcralrx`jxzto~xh}jelzsxjun{exjc^ykyt``rao~bcybldy~eonpvzwlmti}l~_t_qmjxdzrgkgcrpy{d{_b|s`nrhtqslsuhfza}^cll|zxffoxgzce__^`uscp__kkydxc`z_lbdymzn|y~l~fu^qxwowdzrvkm~raeobzxsfdqbk{^tqnuh^e}{erqwaekdbd^m~njxchykv_hn_xoftzvwe{~btnehnm}sxljgfm`tn~tsn^}ob~z_csviuw|mfpeou_gvb|rv~ob{``mcttdrbnmq_xtdlm^nymndhhz|{jmqv_mebesniuwl_kiahhsoffpxitsda_`cxti|~yh`ionmw_qelro|jujnl^zlueutz^fs~}_r{{amuf{~j`ll|~}aa_k{mppqk_alpqztttfl{po{|`jvx^~m}meoclfpq_znxmnpb`cipjk~mvfe_z_gampmt{qhtab^e|u{b}pgrezp^nk`}yxdythszvx`kiszu|t^qqn}ngkomgno|anoifcghj`yoaaz|{jllt{fr`vg_wui~lrfkoy|mrfvdeggjgyeqqf|yigbrv`xeaqyrwzvydji_ph`^jkhgcevvusgr~{lj_rpddne~vsld~jto|wcfwfxqea|nmzqsfv}mhz{z|a`khplnbjeo~jx`tweqhxsfo_v^ya~h~~jbrfbw{pumj`udzk}ee{ae{dtbbnb_rjhdstqev{^nc}ajme_zm`|ehf_y|wdzte}b~^^upt~`luxlxkl}p_}{hhurhs`mpwx_|suaeuqpzi{c|dpp|``yvcalo`dlisksa`h{ts~wk{q|thfh~_jua^vctie_s_aq|s`l~_spte_tisijxugxxvqsu_unxmwefnnuqd^{kdrn~hzeyz}l|idhdscxjve{edbyjtlnf~ajvw`vkyhhbnngbfietvdww}sispbx_w^oqr|ylizu`ictmz{ncjs|hx_u~sld^kcdusn~khgitgfp}kwule|wumzmqubcvlkddo~rhc^byxv`ywwcpja`ot``xpxbetiyj|gfz^eojttpt}x^c^~}ii|eh{^q^}e{mtrmyhudohoe|nwzlt`lin{djgqqyk}ooxprpcwdfyhyywtr}^^vfo|gqf~`vcw_kavpwg_}dziq`|ag_^`fnvbsuycc__q`dxltlestqxpdmolpm{apezkt^|{{lgol`e^wd`mmrw}ms_y^~|ihercmx~drwmedhmwrzqkrfi``rlm_ikinztvmbeqz^hc}gnmb^dns{cd`x{l}gyjdnik^kxegork~kuqvvy`tmxlqo^ldkarsujsppqh`y}|~gvexk^rue`tncd^tf^ynt}fhjxa~nnfh|qdkxo_^csjewek`qy^b^_fahj^vqlym{oss`tp_orzloqkvroiop{jaldoqeervfxsyrxmodb}}gz_kkqxj~c{eekn_jwluik}yao`cr|~ufemyo||}uevqzmdzdutdvrjfrx`tc}b|nirmqttpume}mfj}ld^{nchomqxfnu_mev_p}~h}_lgeo~rklo{tsdgrqkslk^{vsqyg}aysegzjgyi`npiw}ayxc~ea~u^n{pzfagxr}wlrq{^hj|s|esqxqv`va{kmjvuuyl~lk`xtlmmby|{u{mkvk....

(this file is 20 MB long)
```

`notes.txt`
```
(really, huge, about 1 gb in size containing 2 numbers per line)
```

`script.py`
```py
from Crypto.Cipher import AES
import base64
import random

key = b'Nf8TLi75CSKLDPN8'
nonce = b'Nf8TLi75CSKLDPN8'

def convert(s):
    if not s:
        return 0
    return ord(s[-1]) - 48 + 10 * convert(s[:-1])

def check(spl):
    tmp = 0
    for x in spl:
        if x - tmp >= 0:
            tmp = x
            pass
        else:
            return False
    return True

def convert_spl(spl):
    while not check(spl):
        random.shuffle(spl)
    return spl


def decrypt1(message, notes):
    a=""
    b=""
    cnt = 0
    ret = ""
    for i in notes:
        if(ord(i) >= 48 and ord(i)<=57):
             a += i if (not (cnt & 1)) else ""
             b += i if (cnt & 1) else ""

        if(ord(i) == 10):
            A = convert(a)
            B = convert(b)
            spl = [ord(x) for x in message[A:B+1]]
            spl = convert_spl(spl)
            ret += chr(spl[0])
            a=""
            b=""

        cnt+= (ord(i) in [10,32])

    return ret


def decrypt2(encrypted_message, key, nonce):
    encrypted_message = base64.b64decode(encrypted_message)
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_text.decode('utf-8')

f = open("encrypted_password.txt","r")
message = f.read()
f.close()

f=open("notes.txt")
notes = f.read()
f.close()

d_message = decrypt1(message, notes)

decrypted_message = decrypt2(d_message, key, nonce)
f=open("out.txt","w")
f.write(decrypted_message)
f.close()
```

Its heavily implied that `script.py` is responsible for reading and using the data in `encrypted_password.txt` and `notes.txt` to obtain something thats subsequently written into `out.txt`.

We see `decrypt1()` and `decrypt2()` at play, so lets start with `decrypt1()`. We observe that `decrypt1` reads every character in `notes.txt`, and if `48 <= ord(i) <= 57` (i.e. "0123456789"), adds it to a variable `a` if `cnt`, else `b`. We also see that upon reaching a `' '` character or a `'\n'` newline character, `cnt`'s polarity (as in even/odd) is swapped letting the subsequent numbers be added to `b` instead of `a` and vice versa.

We also see that when the `'\n'` character is reached, it calls `convert()` on the number string of `a` and `b`. We see that `convert()` is a simple recursive algorithm that essentially performs string to integer.

It then takes all character data in message from starting index `A` to end index `B`, then runs `convert_spl()` and adds the first character to `ret`. Looking at `check()` first we see it basically checks if a given array is sorted in ascending order; `convert_spl()` calls a while loop that shuffles an array till `check()` is satisfied; We see that a clearly inefficient algorithm is being used. Bogosort!

### Speeding Up Decrypt1
---

So, `decrypt1()` itself seems to take up the most time. I've tried to code it much efficiently in python with
```py
from tqdm import trange

def decrypt1(message):
    try:
        f = open('notes.txt','rb')
        f1 = open('de.txt','a')
        nlen = 60593484
        for i in trange(nlen):
            a,b = [int(j) for j in f.readline().rstrip().split(b' ')]
            assert b-a > 10000
            spl = min(message[a:b+1])
            f1.write(chr(spl))
    except KeyboardInterrupt:
        print(f"INTERRUPTED, see line {i}")
```
yet I was told from `tqdm.trange` that it would take a LOT of hours for my program to finish running, more than the alloted 24 hour time limit!

Thus, to speed up `decrypt1()` I'd incorporated two techniques. The first was to transfer everything over to `cpp`, which runs many times faster than `python`. A direct conversion took about an estimated 40 minutes or so to finish running.

I made another optimisation, by storing every lowest character for every `10000` characters in `encrypted_password.txt`. Then, when I went to find the minimum character within a range [A:B], instead of taking `O(B-A)` time it would take `O((B-A)/10000 + 10000)` time ish instead. This gave the `decrypt1()` output in 5 minutes or so.

```cpp
#include <fstream>
#include <stdio.h>
#include <iostream>
using namespace std;

int main() {
	char* pwdata = (char*)malloc(20000001 * sizeof(char));
	FILE* pwfile = fopen("C:\\Users\\Warri\\Downloads\\dist-bee-password\\encrypted_password.txt", "r");
	fread(pwdata, 20000001, 1, pwfile);
	char* pwmins = (char*)malloc(2000 * sizeof(char));
	memset(pwmins, 0, sizeof(pwmins));
	int minchar = pwdata[0];
	int j = 0;
	for (int i = 1; i < strlen(pwdata); i++) {
		if ((int)pwdata[i] < minchar) minchar = pwdata[i];
		if (i % 10000 == 0) { pwmins[j] = minchar; minchar = 0xff; j++; }
	}
	cout << pwmins << endl;
	ifstream notes("C:\\Users\\Warri\\Downloads\\dist-bee-password\\notes.txt");
	int a, b;
	char* m1 = (char*)malloc(60593485 * sizeof(char));
	memset(m1, 0, sizeof(m1));
	int m1ptr = 0;
	int cnt = 0;
	int aptr, bptr;
	while (notes >> a >> b) {
		cnt += 1;
		if (cnt % 100000 == 0) {
			cout << cnt / 100000 << "/" << 606 << endl;
		}
		aptr = a / 10000 + 1; // ceil
		bptr = b / 10000; // floor
		minchar = 0xff;
		for (int i = a; i < aptr * 10000; i++) {
			if ((int)pwdata[i] < minchar) minchar = (int)pwdata[i];
		}
		for (int i = aptr; i < bptr; i++) {
			if ((int)pwmins[i] < minchar) minchar = (int)pwmins[i];
		}
		for (int i = bptr * 10000; i <= b; i++) {
			if ((int)pwdata[i] < minchar) minchar = (int)pwdata[i];
		}
		m1[m1ptr] = minchar;
		m1ptr += 1;

	}
	FILE* outfp = fopen("C:\\Users\\Warri\\Downloads\\dist-bee-password\\dm1.txt", "w");
	fwrite(m1, strlen(m1), 1, outfp);
	cout << "Done" << endl;
}
```

### Getting the Flag
---

We then run through `decrypt2()` as normal, which performs `base64decode -> AES_EAX_decrypt` on the `decrypt1()` output.

```py
from Crypto.Cipher import AES
import base64
import random

key = b'Nf8TLi75CSKLDPN8'
nonce = b'Nf8TLi75CSKLDPN8'


def decrypt2(encrypted_message, key, nonce):
    encrypted_message = base64.b64decode(encrypted_message)
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_text.decode('utf-8')

d_message = open("dm1.txt",'rb').read()
decrypted_message = decrypt2(d_message, key, nonce)
f=open("out.txt","w")
f.write(decrypted_message)
f.close()
```

`out.txt` contains a transcript of the Bee Movie, we pipe it through `grep` to obtain our flag!

```
warri@warri:/mnt/c/Users/Warri/Downloads/dist-bee-password$ cat out.txt | grep grey{
grey{Be3-kN0w5-rMq-krdy}
```