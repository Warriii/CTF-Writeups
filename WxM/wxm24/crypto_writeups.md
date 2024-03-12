# Warri's WxMCTF24 Crypto Writeups

## Crypto 1 - Detective Pikachu!
We get some strange text made up of only whitespaces:
```txt
   			    
	
     		 	  	
	
      	     
	
     			    
	
     		 	  	
	
...
```
Putting it through a whitespace interpreter (https://www.dcode.fr/whitespace-language) we get:
```txt
pi pi pi pi pi pi pi pi pi pi pika pipi pi pipi pi pi pi pipi pi pi pi pi pi pi pi pipi pi pi pi pi pi pi pi pi pi pi pichu pichu pichu pichu ka chu pipi pipi pipi pipi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pikachu pi pikachu ka ka ka ka ka ka ka ka ka ka ka pikachu ka ka ka ka ka ka ka ka ka ka pikachu pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pikachu ka ka ka ka ka ka ka ka ka ka ka ka ka ka pikachu pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pikachu ka ka ka ka ka ka ka ka ka ka ka pikachu ka ka ka ka ka ka ka pikachu pi pi pikachu ka ka ka ka ka ka ka ka ka ka pikachu ka ka pikachu pi pi pi pi pikachu pi pi pi pi pi pikachu ka ka ka pikachu pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pi pikachu pi pi pikachu pi pi pi pi pikachu pichu pichu pichu pikachu
```
We then insert this through a pikalang interpreter (https://www.dcode.fr/pikalang-language) getting us the flag,
`wxmctf{pika_chewy}`

## Crypto 2 - Common Faults
We receive two files here.

`ciphertext`
```py
n: 19290563578327453949336521542006226917305579089238611319340418865328530239156980001148287094794597245123342342649855430461737481257157770687174830619431639754196595918514001386358652631605986698185365603862366462464354475435147445345755769464304858043419123264809730783029021355227182841798894442177927483078138507520231852246431337982584453172947670828725583176749755687698515274495507626279949858815116849415334900660204540013242983358025753756615290790683594556065352249470422727993888306130121329010803896204476837596104298196365868904948872583257714213914727558162469953472832667212915079478881070361647287015227
e: 65537
c: 18651644693683054500673994100601459545925853716962588421795414933698538684984482916159946002793177633717078905622925228071773514366713805302237236714442930364546559314843428959267114429105532705487024783842788301859773264126504840457220646595816221419555235469896275131927965495584860587878045966243673199696688948322690985185539666907621802019743685283044241203593017376586867315108177287787350717174687351233595394833663147023752431508036796976955242838752921981607946587816363632082619157176008888168613496313967922129619654124493807707014504868657108592724853408470318017578423378680540301597591896080826893418241
```

`past_keys`
```py
13634682244062493209535317287378641081468326517990274037123601085280572670602789584069432503759192981382751243322868632173207382308590505381868038691157029751197947611801438815439114317669390894439347417597015575948420494845824231713994873429669784068959172248647315244747955126515471501639261048607673430977766353168360899715115780670497208055271229956880676434385766427005244661461855609455012007039926208637486473683227550907779840335176305454862375732557792415469369471661608287326466460118968875765493925387466496814365453679408574167815228475613140811278611202066288944857617091672801857028333449173119090670241

19964983837564150411024495992270143343224352835765057169734081076642228813263457569979190650544193340800914243895854826087042162594251886725077648132556794214095210616197588600689459909397443955414906889667005526739156243943887882781573083921998413193662975688733113932627755513195805172201497582240513596364290634349906060658866718923795368935780413653309419014141004476669883952732392648498562596039131382791810185375707845850249814127135949467737591865028026966541459883627209958073475584455015064316444973758618819007991258073933750412418042479738466906231572923008071170517817535197651740906934300866642107858183

18889328381404668239720333947934830952021287651171901575256780880957068941326169892438524902705323260024732507400785222437913768639831014130872371288804587698332704684945760140233969917670052662471487155905274264197390617304032853073323543688429426122827473518872905186161574080142082855758748090023203653452274224008963436004027250568814023242041198685790935928653673399787054550871277508263662299871520040773994372406037802234852215009154861027306663029970599897806038582201601532772836238680370150414651420748241644520345132782909147139356403587754710180919137863113442282833804581007490529700367619118954135063751

12598389218740140579461608819512259513494605530748067612747825041616399381371807275747788343676681827239129433183632854227258697902285389930557767211969915989365183211420094806198856586018451759054123658471825060684141242370427695601995025226952809136986945616367486926003025108426533321358047129662997374286849027344721760207827550569131538156348063634204970341941721792781117086842691532456624308207594602626519584284663525182283083320102637173307906191855337992766432770113156372011280132124377352928426642537421627761138020904862611170348392774549500150425632747028586581326021622542058437652720468860629584865747

21009597895151991048957080170283815124260757619871599890323047085691338521114639475957087372180979723455575973768756433127965625839418928424865102814917604858107149143481117676395343080670586313482525295203828634102336673836504691701388647757453892313580600773332992094821357730728999381704688704666334340399942407837274583499050227490215885234348128507862215747188343522345736299034937455315236979763696197340211938298583511610123018063947628267553768524953595022011707343968101085316695416036590429502054422942272546535501327183872646581209806652969987269459577425816345309038852843425590500841893635274497284827263

15999189908967656407582517571287084079009874307412533585119810690472438620033611891212412301627441390518011580994873792338143422990125462384771294364773044005227846516389333140902823783545969640857193819114190931009861387456890668412818563889963198398406417699016221797984824021001367209338803575158636154621239690229908324761944294705169498519999617206289087244067197435156019292801546344393188500044301101889597577852797505222180244585145034689731841704995220902355407546203905607669145834523415106875959579712857719202326213910720529818449678642037147838398385835679292883721803482069360902175587332741595723208527

17060829917540070745030292243781553638590091899314190818159250455963505841792701295664796094574203198946132858945447916932084920280787094725952480768608869535012148171388285709119561558761672707862399888726042737101412487275888833989686715122957022437075714404243904633807300584831564725389538820125109408622298767397251766024535550323254342021712647181920368561517170975255002314338951076619020485429628802221772135646119959249072928741459990628737363931494652192292886508297052373778394814517125324281588928316855934631980781369461739044251458178241544679774280264290527571769804410623822046481731374693508172372433

14738513653498871549706819441346801177681246497723103663948270875796195110701206104587855600472107987592027677090098796239789666192874576939786629214894902983817232924925377203463734157036494332795840259905108129790769097897120533647954453217977363060830807541201842623609324654140547233879195533112035980256914768006116354187956163751273193869929239348303807265085534061539453683307581456336166630229280475960695656193373161574640186013831556530259722906801185586577884403226762727312395475054559080821971932963060901989676999431551821286226026673473225602684580072913417554771318259964900830081247371572868207317703

18286405907934052226952046558180358257132137807342087990642195125902901347015767746217962913187157765450575178004580338595787658186086828103650848031067019548430317554317532155902277266893473765238972821710205429510303271429851717543179620013622720935258534698063616461069254822435315713510034206051306435695294352957309546770853848980015534041585461499082441214678038815962482833001461225568481090673110402278246867487864633176526859926494463634917147485681085143328702519961588713293247646453108381251417120898674843582541191156516387817503009654497920230002218581920538258572965874552929213065954817686800766402461

11110937934725565334525287762252989696996144862651515395206570292516501925891388375766411922725150870545763552802007496369934612683970714218976131506622059754556962743767916956590601393140800471771765776301666233327658079412004944744190618660025637101605417891490721248626758398291400837922059009366445157178773268861198868995610021237344083896199826161321816696006788755036399036250768357325111273643210926020134647841775138729470518698156750892291732722154586419321866274919388488443933115188932775563516997243865346112199481075271268378278930516184559858867227866956260033866470322508710935995805194855125539360149
```

It seems heavily implied that `RSA` encryption is used here, with the terms `n`, `e`, and `c`. In RSA, we encrypt messages `m` with `c = pow(m, e, n)`. The difficulty of RSA lies in that `n` is hard to factor, and if we could factor `n`, we can compute the euler totient function of `n` to obtain a value `phi`, which satisfy the property wherein for any positive integer `x < n`, where `x` is also coprime to `n`:

`pow(x, phi, n) == x`
Thus, by computing some value `d = pow(e, -1, phi)`, with `d` the modular multiplicative inverse of `e`, we obtain a value `d` such that `e*d == 1 mod phi`

This enables us to perform `pow(c,d,n) = pow(m, e*d, n) = pow(m, 1 + k*phi, n)` for some integer `k` == `pow(m, 1, n) == m`. Thus is how RSA Decryption works.

The challenge description states that there is `a COMMON issue with his vault`, which implies something  common amongst the past keys! We also know that as he was generating keys until one contained `271828`, and seeing how the `n` in `ciphertext` contains said number string, the past keys are past ns!

A common thing that might exist among the ns would be a common factor. We use Python's `math.gcd()` to find the greatest common factor between our `n` and one of the `ns` in `past_keys`...voila, we get one of the prime factors of `n`!

We then use this to factorise `n`, and perform standard `RSA Decryption` on the ciphertext to obtain our flag as follows:

solve.py
```py
from math import gcd
from Crypto.Util.number import isPrime

int_to_bytes = lambda x:x.to_bytes( (x.bit_length() + 7) // 8, "big")

n1 = 13634682244062493209535317287378641081468326517990274037123601085280572670602789584069432503759192981382751243322868632173207382308590505381868038691157029751197947611801438815439114317669390894439347417597015575948420494845824231713994873429669784068959172248647315244747955126515471501639261048607673430977766353168360899715115780670497208055271229956880676434385766427005244661461855609455012007039926208637486473683227550907779840335176305454862375732557792415469369471661608287326466460118968875765493925387466496814365453679408574167815228475613140811278611202066288944857617091672801857028333449173119090670241
n = 19290563578327453949336521542006226917305579089238611319340418865328530239156980001148287094794597245123342342649855430461737481257157770687174830619431639754196595918514001386358652631605986698185365603862366462464354475435147445345755769464304858043419123264809730783029021355227182841798894442177927483078138507520231852246431337982584453172947670828725583176749755687698515274495507626279949858815116849415334900660204540013242983358025753756615290790683594556065352249470422727993888306130121329010803896204476837596104298196365868904948872583257714213914727558162469953472832667212915079478881070361647287015227
e = 65537
c = 18651644693683054500673994100601459545925853716962588421795414933698538684984482916159946002793177633717078905622925228071773514366713805302237236714442930364546559314843428959267114429105532705487024783842788301859773264126504840457220646595816221419555235469896275131927965495584860587878045966243673199696688948322690985185539666907621802019743685283044241203593017376586867315108177287787350717174687351233595394833663147023752431508036796976955242838752921981607946587816363632082619157176008888168613496313967922129619654124493807707014504868657108592724853408470318017578423378680540301597591896080826893418241

p = gcd(n, n1)
q = n // p
assert p > 1 and q > 1 and p*q==n and isPrime(p) and isPrime(q) # i.e. we've the full prime factorisation of n

# having a full prime factorisation enables us to compute the euler totient function of n as,
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(int_to_bytes(m)) # b'wxmctf{CommOn_F@u1t_0R_cOMm0N_f4ctoR?}'
```

## Crypto 3 - racing
We obtain the following python server-side script:
```py
import os
from Crypto.Util.number import *

def rng():
    m = 1<<48
    a = 25214903917
    b = 11
    s = bytes_to_long(os.urandom(6))
    print(f's = {s}')
    while True:
        yield (s>>24)%6+1
        s = (a*s+b)%m

r = rng()
a = 25214903917 
b = 11 
m = 1 << 48

prev = next(r)
d = {i:[0]*6 for i in range(6)}
for i in range(100):
    nval = next(r) - 1
    d[prev][nval] += 1
    prev = nval
    print(nval, end=" ")
print(d)
exit()

cpuPlayers = [0]*6
yourPlayers = [0]*6

def printBoard(cpu, your):
    board = [[] for i in range(100)]
    for i in range(6):
        if cpuPlayers[i]!=None:
            board[cpuPlayers[i]].append("C"+str(i))
        if yourPlayers[i]!=None:
            board[yourPlayers[i]].append("Y"+str(i))
    print(*board)

cpuScore = 0
yourScore = 0

while any(i!=None for i in yourPlayers) and any(i!=None for i in cpuPlayers):
    printBoard(cpuPlayers, yourPlayers)
    #CPU goes first

    # chooses CPU player
    x = next(r)-1
    while cpuPlayers[x]==None:
        x = next(r)-1

    cpuPlayers[x]+=next(r) # moves CPU player

    for i in range(6):  # overtake any player pieces
        if yourPlayers[i]==cpuPlayers[x]:
            yourPlayers[i] = None
    for i in range(6): # move out of board to win 1 point
        if cpuPlayers[i]!=None and cpuPlayers[i]>=100:
            cpuPlayers[i]=None
            cpuScore+=1
    printBoard(cpuPlayers, yourPlayers)
    #your turn next
    x = int(input())
    assert 0<=x<=5 and yourPlayers[x]!=None
    yourPlayers[x]+=(next(r)-1)%3+1 #player disadvantage
    for i in range(6):
        if yourPlayers[x]==cpuPlayers[i]:
            cpuPlayers[i] = None
    for i in range(6):
        if yourPlayers[i]!=None and yourPlayers[i]>=100:
            yourPlayers[i]=None
            yourScore+=1

cpuScore+=6-cpuPlayers.count(None)
yourScore+=6-yourPlayers.count(None)
if cpuScore==0 and yourScore==6:
    print("Congrats on winning! here's your flag")
    print(os.environ.get("FLAG", "wxmctf{dummy}"))
else:
    print("Not good enough or you lost :/")
```
A quick python reverse engineering nets us the following idea:
We play a game on a 100-size board. We start with 6 individuals labelled `Y0, Y1, Y2, ..., Y5`, and the CPU starts with `C0, C1, ..., C5`.

Every turn, the CPU uses an `LCG` (Linear Congruential Generator) to obtain a random numbers from 0 to 5. The CPU uses this to:
- Select a random CPU icon from `C0, C1, ..., C5`, so long as the CPU icon exists
- Move said CPU icon from 1 to 6 spaces across the board

Similarly, every turn we as the player get to pick an existing icon from `Y0, Y1, ..., Y5`. The same `LCG` is then used to move the icon from 1 to 3 spaces across the board.

There is a catch, where if a player moves an icon `X` to a square occupied by another player's icons, the other player's icons are overtaken and consumed (i.e. they no longer exists). The game ends once one player (CPU or Player) runs out of icons. Additionally, whenever an icon reaches the end of the board, the relevant player's score is incremented by 1 (but this doesnt matter in our solution)

At the end of the game, the player and CPU's scores are added by the number of their corresponding icons left. We get the flag if the game ends with our `cpuScore==0 and yourScore==6`.

One way to do this is to find a vuln to the `LCG`, use it to predict the rng values and then manipulate it to win. The `LCG` works by taking some state `s`, performing `a*s+b % 2**48` for known values `a` and `b`, and then returns the upper 24 bits of s modulo 6, added by 1.

Except we don't necessarily have to do that. Due to how low the number of player and cpu icons are, we can pretty much brute force this until we get lucky. To achieve `cpuScore==0 and yourScore==6`, we can simply just consume ALL cpu pieces, and keep ALL our pieces alive.

We do this using the following greedy algorithm,
```py
FOR EVERY turn DO:

    IF COUNT(players) < 6:
        # we lost one of our players
        EXIT()
        
    IF furthestCpuPos > furthestPlayerPos:
        CHOOSE(furthestPlayer) 
        # the idea is to move the furthest player to hopefully overtake the furthest cpu piece
    ELSE:
        FOR player IN playersSortedByAscendingPosition:
            IF furthestCpuPos > playerPos:
            # move the next closest player to the furthest cpu icon and hopefully consume it
                CHOOSE(player)
                BREAK
```

Eventually we get a successful output, as shown:
```
['C0', 'Y0', 'C1', 'Y1', 'C2', 'Y2', 'C3', 'Y3', 'C4', 'Y4', 'C5', 'Y5'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C0', 'Y0', 'C1', 'Y1', 'C2', 'Y2', 'Y3', 'C4', 'Y4', 'C5', 'Y5'] [] [] [] ['C3'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
0
['C0', 'C1', 'Y1', 'C2', 'Y2', 'Y3', 'C4', 'Y4', 'C5', 'Y5'] [] [] ['Y0'] ['C3'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C0', 'Y1', 'C2', 'Y2', 'Y3', 'C4', 'Y4', 'C5', 'Y5'] [] [] ['Y0'] ['C1', 'C3'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
0
['C0', 'Y1', 'C2', 'Y2', 'Y3', 'C4', 'Y4', 'C5', 'Y5'] [] [] [] ['C1', 'C3'] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C0', 'Y1', 'C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C4'] [] [] ['C1', 'C3'] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
['C0', 'C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C4'] ['Y1'] [] ['C1', 'C3'] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C4'] ['Y1'] [] ['C1', 'C3'] ['C0'] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C4'] [] ['Y1'] ['C1', 'C3'] ['C0'] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C4'] [] ['Y1'] ['C1'] ['C0'] ['Y0'] [] [] [] ['C3'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
0
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C4'] [] ['Y1'] ['C1'] ['C0'] [] [] ['Y0'] [] ['C3'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] [] [] ['Y1'] ['C1'] ['C0'] ['C4'] [] ['Y0'] [] ['C3'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
0
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] [] [] ['Y1'] ['C1'] ['C0'] ['C4'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] [] [] ['Y1'] ['C1'] [] ['C0', 'C4'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
['C2', 'Y2', 'Y3', 'Y4', 'C5', 'Y5'] [] [] [] ['Y1'] [] ['C0', 'C4'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C2'] [] [] ['Y1'] [] ['C0', 'C4'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
['Y2', 'Y3', 'Y4', 'C5', 'Y5'] ['C2'] [] [] [] ['Y1'] ['C0', 'C4'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['Y2', 'Y3', 'Y4', 'C5', 'Y5'] [] [] [] [] ['Y1'] ['C0', 'C2', 'C4'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
['Y2', 'Y3', 'Y4', 'C5', 'Y5'] [] [] [] [] [] ['Y1'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['Y2', 'Y3', 'Y4', 'Y5'] [] ['C5'] [] [] [] ['Y1'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
2
['Y3', 'Y4', 'Y5'] [] ['C5'] ['Y2'] [] [] ['Y1'] [] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['Y3', 'Y4', 'Y5'] [] [] ['Y2'] [] [] ['Y1'] ['C5'] [] [] ['Y0'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
Congrats on winning! here's your flag
wxmctf{u_won_the_r4c3_0mgGG!!}
```

## Crypto 4 - Espionagey Crafty Clues
(fun fact, i'd blooded this challenge and raised a vulnerability in the code)

We get a binary `note.txt` with values:
```
01110000 00100000 00111101 00100000 00110110 00110100 00110111 00110110 00110001 00110101 00110111 00110011 00110010 00110110 00111001 00111001 00110100 00110111 00110000 00111001 00100000 00001010 01100001 00100000 00111101 00100000 00110011 00111000 00110010 00110100 00111001 00110010 00110010 00110100 00110110 00110001 00001010 01100010 00100000 00111101 00100000 00111001 00110001 00110111 00110111 00110100 00110010 00110111 00110001 00110101 00110011 00001010 01101011 00110001 00100000 00111101 00100000 00110110 00110001 00110110 00110010 00110010 00111000 00110000 00110101 00111001 00111001 00110010 00111000 00110011 00111000 00001010 01101011 00110010 00100000 00111101 00100000 00110101 00110010 00110111 00110101 00110010 00110011 00110000 00110101 00110101 00110111 00110110 00110101 00111000 00110010 00001010
```
we decode this binary using any binary to text translator (https://www.rapidtables.com/convert/number/binary-to-ascii.html) to get:
```py
p = 6476157326994709 
a = 3824922461
b = 9177427153
k1 = 61622805992838
k2 = 52752305576582
```

Let's keep these params in mind for later.

We also have some `jumbler.py`
```py
import random
gen = [XXXXXXXX]  # Past generator points
x1 = []  # First half of the x-coords
x2 = []  # Second half of the x-coords
y1 = []  # First half of the y-coords
y2 = []  # Second half of the y-coords
for i in gen:
    x = str(i[0])
    y = str(i[1])
    x1.append(x[0:len(x) // 2])
    x2.append(x[len(x) // 2:len(x)])
    y1.append(y[0:len(y) // 2])
    y2.append(y[len(y) // 2:len(y)])
for i in range(32767):
    random.shuffle(x1)
    random.shuffle(x2)
    random.shuffle(y1)
    random.shuffle(y2)
coords = list(zip(x1, x2, y1, y2))
for c in coords:
    print(c)

# Output
# ('6083541', '70208246', '12183899', '05162877')
# ('1152823', '0965475', '30207985', '05181068')
# ('6153634', '54008046', '30816494', '06143057')
# ('5598253', '9499216', '10641890', '08809654')
# ('40427750', '97139558', '4993690', '73140782')
# ('58544347', '0898815', '2423158', '32131699')
# ('50076906', '4590531', '7041427', '11019654')
# ('1086272', '6907039', '3698478', '19160446')
# ('3824463', '77724465', '15155162', '41560946')
# ('7169758', '0435191', '6696910', '63790720')
# ('54742595', '84679407', '7960660', '09396231')
# ('21573556', '85818785', '26820913', '14682461')
# ('2538734', '8155665', '8039628', '97583027')
# ('173312', '1822597', '14767541', '59813618')
# ('57621461', '50600003', '9655056', '48435717')
# ('13529234', '20347874', '5467054', '07539449')
# ('4479258', '52052811', '19942058', '72408483')
# ('730514', '9075384', '2536379', '82436556')
```
which produces a series of jumbled values `x1, x2, y1, y2`.

For example, given 3 points `(x00|x01, y00|y01), (x10|x11, y10|y11), (x20|x21, y20|y21)`, with `|` as just string concatenation, we might get something like,

```
(x10,x01,y00,y21)
(x00,x11,y20,y11)
(x20,x21,y10,y01)
```
We also know that the points themselves are "generator points" of something. Let's check the challenge name. E-something...C-something...C- aha, it's related to `ECC`, or rather `Elliptic Curve Cryptography`!

Now ECC as a whole is a rather confusing subject to newcomers, so I'd recommend the following article as a primer: https://arstechnica.com/information-technology/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/

In our case, we define our curve with a prime modulus `p`, and two coefficients `a` and `b`, and we notice that these values are exactly those provided in our decoded binary values from before!

With the parameters of the curve sorted, we can easily brute through possible `(x,y)` coordinate pairs from the jumbled output to recover the de-jumbled generator points. For every possible `(x,y)` combo, we only need to see if they exist on our curve.

One way to do this would be to manually verify if the curve equation holds true at that point, i.e. `y**2 == x**3 + ax + b (mod p)`. We can also use `Sagemath`'s Elliptic Curve functionality to verify points as shown:

```py
items = [('6083541', '70208246', '12183899', '05162877'),
('1152823', '0965475', '30207985', '05181068'),
('6153634', '54008046', '30816494', '06143057'),
('5598253', '9499216', '10641890', '08809654'),
('40427750', '97139558', '4993690', '73140782'),
('58544347', '0898815', '2423158', '32131699'),
('50076906', '4590531', '7041427', '11019654'),
('1086272', '6907039', '3698478', '19160446'),
('3824463', '77724465', '15155162', '41560946'),
('7169758', '0435191', '6696910', '63790720'),
('54742595', '84679407', '7960660', '09396231'),
('21573556', '85818785', '26820913', '14682461'),
('2538734', '8155665', '8039628', '97583027'),
('173312', '1822597', '14767541', '59813618'),
('57621461', '50600003', '9655056', '48435717'),
('13529234', '20347874', '5467054', '07539449'),
('4479258', '52052811', '19942058', '72408483'),
('730514', '9075384', '2536379', '82436556')]
x1 = []  # First half of the x-coords
x2 = []  # Second half of the x-coords
y1 = []  # First half of the y-coords
y2 = []  # Second half of the y-coords

for i,j,k,l in items:
    x1.append(i)
    x2.append(j)
    y1.append(k)
    y2.append(l)
p = 6476157326994709 
a = 3824922461
b = 9177427153
k1 = 61622805992838
k2 = 52752305576582

E = EllipticCurve(GF(p), [a, b])

for i in x1:
    for j in x2:
        x_coord = int(i + j)
        try:
            px, py, _ = E.lift_x(Integer(x_coord))
            for v in y1:
                for w in y2:
                    y_coord = int(v+w)
                    if y_coord == py:
                        P = E.lift_x(Integer(x_coord))
                        print(P)
        except ValueError:
            continue
```
It's a bit scuffed, but this prints out all of our points,
```
(608354197139558 : 3081649463790720 : 1)
(11528236907039 : 2682091372408483 : 1)
(615363485818785 : 1994205848435717 : 1)
(55982539075384 : 669691011019654 : 1)
(4042775070208246 : 803962806143057 : 1)
(5854434754008046 : 546705409396231 : 1)
(5007690677724465 : 369847814682461 : 1)
(10862721822597 : 3020798508809654 : 1)
(38244630435191 : 1515516259813618 : 1)
(71697588155665 : 499369005162877 : 1)
(5474259584679407 : 1218389919160446 : 1)
(2157355650600003 : 242315807539449 : 1)
(25387340898815 : 1064189097583027 : 1)
(1733124590531 : 1476754132131699 : 1)
(5762146152052811 : 704142773140782 : 1)
(1352923420347874 : 796066082436556 : 1)
(44792589499216 : 253637905181068 : 1)
(7305140965475 : 965505641560946 : 1)
```
Note that sagemath stores `EllipticCurvePoint` classes as `(x,y,_)`. If I remember correctly, `_` is a `1` if the point exists and `0` if it doesn't.

But we have dejumbled all the points now, but which point do we need? The chall description states, `using the coordinate with the highest order`. What is an order?

In Cryptography, we oftentimes deal with things that have cycles, or are cyclic in nature. Consider RSA with the sequence `1, m, m*m, m*m*m, .... mod n`.

Eventually at some point this will lead back to `1`, or `m**0` again. Suppose we find a minimum non-zero positive integer `x` s.t. `m**x == 1`. We call this value the `order` of element `m` in the `multiplicative (*) group of integers modulo n`. The more knowledgeable cryptographers may notice that this `order` will always be a factor of the euler totient function of n. Why `1`? Well because in our group thats the `Identity element`, where any element multiplied with the identity equals itself! 

(we use multiplication here bcos we have defined this "group of integers" to use "multiplicative" as the group operation in our `multiplicative (*) group of integers modulo n` definition)

The same concept applies in `ECC`. For any given curve we define a `Point at Infinity O`. This point has a special property where it is the identity element of the curve. Any other valid point, upon being added with `O`, will always equal itself. So for any valid point `P` in our curve, its order would be the lowest number `k` such that `k*P (or rather P added to itself k times) == O`.

There's a few ways we can do this. One way would be to determine the euler-totient equivalent of our Elliptic Curve in particular, and then test factors of it from smallest to biggest until the scalar multiplication result gives us `O`. Another method is to just use Sagemath's `EllipiticCurvePoint.order()`.

We add in some lines of
```py
P = E.lift_x(Integer(x_coord))
print(P)
o = P.order()
if o >= omax:
    omax = o
    max_p = P
```
every time we find a valid point to determine the point coordinate with the highest order. We find this to be the point `(4042775070208246 : 803962806143057 : 1)` with order `6476157267195210`.

We are told to then take this coordinate, and "(put it) through one of the most common key exchange systems", "encrypt it with the secret exchange system" and return the "sum of the x and y coordinates of the shared coordinates wrapped in `wxmctf{}`".

It is around then that we note the presence of `k1` and `k2` params in the decoded binary file. One of the most common `ECC` key exchange systems is the `ECDH (Elliptic Curve Diffie-Hellman)`. How it works is that-

Consider Alice with private integer key `dA`, and Bob with private integer key `dB`. We'll suppose they agree on some common generator coordinate `G` on an elliptic curve.
- Alice computes `dA*G` and sends this result to Bob. Note that ECC relies on the fact that computing the result of `dA` from `dA*G` and `G` is hard.
- Bob computes `dB*G` and sends this to Alice

Both users can then compute `dA*dB*G` and use this as their shared key. One could use the x-coordinate of this point as a shared key, for example.

Assuming this is the case, we simply perform `k1*k2*max_p`, getting us the point `(855797017196557, 2154964981299182, 1)` with the sum of its coordinates as `3010761998495739`.

And so we find the flag, `wxmctf{3010761998495739}`

## Crypto 5 - 3-5 Business Days

We are provided with a chall.py file and a server instance to ncat to.
`chall.py`
```py
import os
from Crypto.Util.number import *

ks = [bytes_to_long(os.urandom(16)) for i in range(11)]
s = [250, 116, 131, 104, 181, 251, 127, 32, 155, 191, 125, 31, 214, 151, 67, 50, 36, 123, 141, 47, 12, 112, 249, 133,
     207, 139, 161, 119, 231, 120, 136, 68, 162, 158, 110, 217, 247, 183, 176, 111, 146, 215, 159, 212, 211, 196, 209,
     137, 107, 175, 164, 128, 167, 171, 132, 237, 199, 170, 201, 228, 194, 252, 163, 172, 168, 179, 145, 221, 222, 255,
     98, 184, 150, 64, 216, 157, 187, 147, 97, 152, 148, 190, 203, 193, 62, 143, 56, 156, 153, 236, 188, 134, 230, 83,
     160, 59, 219, 76, 11, 144, 178, 254, 218, 244, 227, 96, 232, 220, 213, 165, 6, 186, 226, 239, 200, 242, 7, 154,
     180, 140, 48, 248, 135, 233, 166, 234, 192, 28, 202, 27, 24, 243, 82, 22, 185, 122, 115, 93, 13, 113, 85, 21, 52,
     55, 38, 57, 78, 66, 46, 71, 189, 195, 100, 103, 1, 72, 208, 99, 105, 74, 101, 94, 61, 240, 25, 23, 18, 84, 138, 87,
     26, 60, 204, 17, 49, 53, 169, 14, 121, 0, 79, 177, 4, 63, 241, 3, 77, 37, 2, 15, 108, 73, 118, 30, 33, 20, 54, 43,
     197, 92, 75, 95, 198, 205, 19, 142, 29, 86, 35, 109, 235, 174, 114, 210, 65, 246, 70, 80, 223, 8, 245, 182, 45, 69,
     149, 129, 90, 224, 39, 206, 130, 126, 10, 88, 91, 253, 58, 89, 81, 117, 34, 106, 124, 41, 51, 229, 40, 44, 238,
     173, 5, 9, 42, 102, 225, 16]
rots = [11, 26, 37, 49, 62, 73, 89, 104, 116]

def pad(msg, l):
    x = l-(len(msg))%l
    return msg+bytes([x]*x)

def lpad(msg, l):
    return msg+bytes(l-len(msg))

def xor(a, b):
    return bytes(i^j for i, j in zip(a,b))


def splitBlocks(pt, l):
    return [pt[l*i:l*i+l] for i in range(len(pt)//l)]


def rot(x, n):
    return ((x >> n) | (x << (128 - n))) & ((1 << 128) - 1)


def doSbox(block):
    bs = lpad(long_to_bytes(block), 16)
    return bytes_to_long(bytes([s[i] for i in bs]))


def encBlock(pt, iv):
    block = pt ^ ks[0]
    block = doSbox(block)
    for i in range(9):
        block ^= ks[i + 1]
        block ^= rot(iv, rots[i])
        block = doSbox(block)
    block ^= ks[-1]
    return block


def enc(pt):
    pt = pad(pt, 16)
    blocks = splitBlocks(pt, 16)
    iv = os.urandom(16)
    ct = iv
    for i in blocks:
        ct+=lpad(long_to_bytes(encBlock(bytes_to_long(xor(ct[-16:], i)), bytes_to_long(iv))), 16)
    return ct


flag = os.environ.get("FLAG", "wxmctf{dummy}").encode()

print(enc(flag).hex())

while True:
    inp = bytes.fromhex(input("Gimme ur plaintext block: "))
    iv = bytes.fromhex(input("Gimme ur iv: "))
    assert len(inp)==16
    assert len(iv)==16
    print(lpad(long_to_bytes(encBlock(bytes_to_long(inp), bytes_to_long(iv))), 16).hex())
```

We are also provided with a server instance to ncat, which we can then use to access an encryption oracle, which lets us put in our own plaintexts and ivs for `enc_block(ptxt, iv)` to be called to see our generated ciphertexts.

As complicated as this encryption scheme is, any good eye can deduce that this is a `pseudo-AES` implementation; That is, it shares certain features inherent to the well known `AES (Advanced Encryption Standard)` encryption algorithm, with the use of an `sbox` for substitution and xoring with 11 different 16-byte keys.

But first let me explain what AES does. More specifically, its generic mode, `AES MODE_ECB`.
Given a plaintext and a key, AES first expands the usual 16 byte input key into 11 different keys. We'll refer to these keys as `RoundKeys`. It also uses an array of 256 unique values that appear 'shuffled' in a sense. We'll refer to this as a `sbox`, or substitution-box

AES then splits the plaintext into 16-byte blocks, and for 11 rounds AES pretty much calls a mix of 4 operations.

1. AddRoundKey(int i) - xors the 16-byte block with `RoundKeys[i]`
2. SubBytes() - replaces every byte in the 16-byte block with `sbox[block[i]]` where `i` is the index of the 16-byte block
3. ShiftRows() - performs an operation on the 'rows' of the 16 byte block. I'll skip this for now.
4. MixCols() - performs an operation on 'columns' of the 16 byte block. I'll skip this for now.

Now you'd probably notice that the encryption system also has its own `AddRoundKey()` and `SubBytes()` functions, and uses them similar to typical `AES`. In place of `ShiftRows()` and `MixCols` however, which are completely absent, it calls `rot(iv, n)` on the provided 16-block IV which xors the current block by a pre-determined value.

Another property to acknowledge is that unless we know all 11 round keys used (represented as `ks = [bytes_to_long(os.urandom(16)) for i in range(11)]`), we cannot decrypt the ciphertext. Since we need to know these values first in order to undo all of the xor operations.

But we do not need to know ANY of the `ks` array to solve for the original plaintext. For there exists a crucial flaw in the implementation - the lack of `ShiftRows()` and `MixCols()` equivalents. 

Consider the `AddRoundKey()`, `SubBytes()` and `rot(iv,n)` calls made in the algorithm to encrypt data. Both `AddRoundKey()` and `rot()` only xors the 16-byte block. Due to the nature of xor, only the `ith` bit of the plaintext block will affect the resultant `ith` bit after the xors. To put it in another way, each output bit is only affected by the same input bit before either functions are called.

As for `SubBytes()`, we see that only the `ith` byte of the plaintext block affects the resultant `ith` byte after the substitution. Each output byte will only be affected by its input byte in the same position before.

Combined, we can see that any `ith` byte of the ciphertext would ONLY be affected by the `ith` byte of the original plaintext! In essence, there is no diffusion in the algorithm! Typically in `AES`, in order to make it difficult to recover the plaintext, every plaintext bit would affect multiple ciphertext bits. `ShiftRows()` and `MixCols()` in `AES` do just that!

Whereas in this case, because `ShiftRows()` and `MixCols()` have been replaced with a very deterministic `rot()` based off of the input `IV` which is constant, and bitwise xor is used with it, there winds up being no diffusion at all! This is where the vulnerability comes into play.

Knowing that the `ith` plaintext byte will singlehandedly impact the output of the `ith` ciphertext byte, we can simply:
1. Send 256 encryption requests of the same byte times 16 to the server, one for each possible byte value (i.e. `\x00\x00\x00...`, `\x01\x01\x01...`, ..., `\xff\xff\xff...`)
2. Maintain a lookup table containing a mapping of `ith input byte with value j` -> `ith output byte value`
3. Reverse the lookup to easily compute the plaintext block before `enc_block()` was called!

And that is all we need to recover the flag. We just need to handle removing the xoring of the previous ciphertext block as seen in `enc()` to recover the plaintext!

```py
from pwn import remote
from tqdm import trange

xor = lambda x,y:bytes([i^j for i,j in zip(x,y)])

r = remote("76eb6c5.678470.xyz", 32473, fam='ipv4')
ct = bytes.fromhex(r.recvline().rstrip().decode())
print(f'ct = {ct}')
nblocks = (len(ct)-16) // 16 # remove iv, divide by 16 byte blocks
iv = ct[:16]

# generate lookup table
lu = []
for i in trange(256):
    r.recvuntil(b"block: ")
    r.sendline((format(i, "02x")*16).encode())
    r.recvuntil(b"iv: ")
    r.sendline(iv.hex().encode())
    lu.append(bytes.fromhex(r.recvline().rstrip().decode()))
r.close()

# uses reverse lookup and recovers flag 1 block at a time
for j in range(nblocks):
    blk = []
    for cnt in range(16):
        found = False
        for p,i in enumerate(lu):
            if i[cnt] == ct[16+16*j+cnt]:
                blk.append(p)
                found = True
                break
    print(xor(blk, ct[16*j:16+16*j]),end="")
# b"wxmctf{this_sbox" + b'_is_definitely_n' + b'ot_secure_what_i' + b's_it_with_bits_1'+ b'_4_and_7???}\x04\x04\x04\x04' 
```

## Conclusion

Thus concludes my writeups for all 5 Crypto challenges. Overall WxMCtf24 was a fun competition involving various cryptographic means whilst also being rather...newcomer friendly, be it intentional or accidental. Looking forward to the Crypto challenges for next year!