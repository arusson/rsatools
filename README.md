# RSA tools

This project is a compilation of several tools written in C to attack RSA, mainly to get familier with the mathematical library [PARI](https://pari.math.u-bordeaux.fr/).

For now, it contains two sets of tools:
- [Factorization of a single RSA modulus with or without the public exponent](#factorization-of-a-single-key)
- [Factorization with partial knowledge of one prime or the private exponent](#partial-key-exposure-attacks)

Other attacks might be added in the future.

Content of this repository:
- `include/`: two headers, one of them is `config.h` and can be modified to adjust some values
- `prgm/`: the main file of the binaries
- `rsa-coppersmith/`: attacks related to Coppersmith's method
- `rsa-single/`: attacks to factor a single modulus
- `utils/`: auxiliaries tools
- A makefile and this README


## Dependencies and installation

This set of tools relies mainly on the mathematic library [PARI](https://pari.math.u-bordeaux.fr/) (it might already be installed on your system if you are already familiar with [Sagemath](https://www.sagemath.org/)).

On a Debian system, you can install the following packages:

```
apt install libpari-dev libpari-gmp-tls7
```

The installation of is easy: clone the repository and `make`.
That's it.

```
git clone https://github.com/arusson/rsatools.git
cd rsatools/
make
```
The programs will be generated into the `bin/` folder.


## Factorization of a single key

The program is `rsa-single` and takes as input a modulus (and an optional public exponent).
- `-n` or `--modulus`: the modulus
- `-e` (optional): the public exponent (only useful for the `factor_small_d` and `factor_wiener` attack
- `--attack` (optional): followed by the name of the attack:
  * `factor_small` 
  * `factor_square`
  * `factor_small_d`
  * `factor_wiener`
  * `factor_fermat`
  * `factor_shared_lsb`
  * `factor_p_pm_1`
  * `factor_cm`

If `--attack` is not provided, **all the attacks will be run**.
The individual attacks are described below.
Some of them have supplementary optional arguments.

There is also the verbose flag `-v` (or `--verbose`) for more verbosity, and `-h` (or `--help`) for help.


### Small modulus

If the modulus is small enough (less than 200 bits), we can factorize the modulus directly with the `factor_small` attack.

```
./rsa_single -n 13835591013508601955356617501157248249972987974212552783 --attack factor_small
```

### Square modulus

If $n = p^2$, we can factorize immediately.
The name of the attack is `factor_square`.

Example:
```
./rsa_single -n 78297508606636734255546527877941659862998377016250455576245379383582442920347363428284313728363073522700726425379782022957275475303153939021034085766104250307515110170603903839197137362974969376662138533915645356136507980050853767364126467841339699197295433089043907534911945250837610122210727857002280456081 --attack factor_square
```

### Small private exponent

It is mandatory to provide the public exponent to run this attack using the `-e` option.

Two attacks are currently available: `factor_small_d` and `factor_wiener`.
In both cases, it works if the private exponent size is less than $n^{1/4}$ (in the case of the Wiener, it is $1/3 n^{1/4}$).
When the whole set of attacks is applied, `factor_small_d` is tested first as it is faster.

```
./rsa_single -n 108925679802284239955001551017681506180164145739691670124361307613981176689733670923774311632395717664402684130443830263937033295748941917653240917714229256396243845478977090813121921418491025509757182629002814915232676429884675193143885477233354472089268619428997934110569939243783923766553598930250989079139 -e 40748325560689123257486527536483510918500840830012157699067275029010630229039582055552209626771400303650355793395740004944852495185054320950198193493963164311430925570877706350889263787470569460632216019425322782108117721415492657825340141267119905429074474964042169876353864031822939977214312487530332981433 --attack factor_small_d
```

> **TODO**: the Boneh-Durfee attack for private exponents up to $n^{0.292}$.


### Close primes attack (Fermat)

A classic attack on RSA, use `factor_fermat`.
We start with $x = \lfloor\sqrt n\rfloor$ and check if $(x + k)^2 - n$ is a square.
When that happens, we have $(x + k)^2 - n = y^2$ so $n = (x + k - y)(x + k + y)$.

We try for $k$ with $0 \leq k < B$ (the bound is 50000 by default).
This attack has an optional arguments to change this bound: `--fermat-bound <VAL>`.

```
./rsa_single -n 17993905914950491436509764609848745889407701208922305196646413621766992846622614476604970908283050717785882685787893383681126527212717999927824594755009072726416107971707905566292701391446727049561208452055259765604283479942581912459438219891123869205353871265616910471441350003239753479583312907703934142271194206788319233033618972618163116022899812760862187551379432607627920372634257141817679924725013054219375317513860159120565072902737014597477023903308248937908414850338991424040608140661465411316830899039534976471493065939613654116614382350055877051913830339187783231007425687358556725613489778331864975405317 --attack factor_fermat
```

### Primes sharing their least significant bits

The previous attack works because $p-q$ is small, in another way the two primes share a lot of their most significant bits.
In the case the primes share their least significant bits, it is also possible to factorize with the `factor_shared_lsb` attack.

This implementation works in a specific case: the primes $p$ and $q$ are such that the number of their least significant bits in common $\ell$ is strictly larger than $\log_2(n)/4$ (the Coppersmith method is not used).

```
./rsa_single -n 95969061182734167696837319881131542496301619959745607926138388622543497901780880433954730696765466102601701328315194465608056191443195349092158675063024346087987310382654581752734608514531607495470218640233801869376908066505672982563829514015829882243253393598696202962408912036484661274078169360611565256113 --attack factor_shared_lsb
```

### Smooth *p-1* and *p+1*

If $p-1$ or $p+1$ is a product of small primes, the attack `factor_p_pm_1` can be used: $$p - 1 = \prod_{i = 1}^m p_i^{\alpha_i},\quad\text{or}\quad p + 1 = \prod_{i=1}^m p_i^{\alpha_i},$$ with $p_i$ prime numbers distinct from each other and $\alpha_i$ their multiplicities.

Several attempts will be made since it will test both cases randomly.
The idea is that we construct a group that has either $p-1$ of $p+1$ elements (when the calculations are made modulo the prime $p$), and we know a multiple of this order (the product of small primes).

By default, the attack expects that the prime factors $p_i$ of $p-1$ or $p+1$ are less than $2^{16}$, and such that prime power factors $p_i^{\alpha_i}$ are less than $2^{64}$.
This behavior can be changed with optional arguments (it can also be changed at compilation time in the configuration file):
- `--p1-prime-bound <val>`: bound on the prime factors $p_i$ of $p-1$ or $p+1$
- `--p1-nbits-bound <val>`: bound on prime power factors $p_i^{\alpha_i}$ of $p-1$ or $p+1$ (the value is given in bits)

Example if the factorization of $p-1$ or $p+1$ has prime factors less than $2^{20}$ (if they appear at most once):
```
./rsa_single -n 96055084779851008502406592815328861630962527251548171954345046797234192459426797362896924679804346924329938014826957203216360063514093668339656861409919126466853568585981567830912323988597067008449335246177088795611091567898342731168911999529785832299470070731151903234363609895839205834594823341024290244799 --attack factor_p_pm_1 --p1-prime-bound 1048576 --p1-nbits-bound 20
```

The higher the bounds, the longer it takes to run the attack.


### The *4p-1* factorization

This factorization method finds a prime factor $p$ of a composite integer if the non-square part of $4p-1$ is a complex multiplication discriminant, from which an elliptic curve of order $p$ can be constructed (which is called an anomalous elliptic curve).

The idea is the same as the previous factorization method:
we construct a group whose order is unknown to the attacker, but a multiple of it is known.
In the previous situation, this multiple was a product of many small primes which is easy to calculate.
In this case, the order is $p$, and the modulus is a multiple.

Two optional arguments are provided:
- `--cm-disc <val>`: a CM-discriminant in absolute value (example: 11)
- `--cm-disc-bound <val>`:  discriminants between $-3$ and "`-val`" will be tested (the default are discriminants $D$ with $|D| < 64$)

Example with `--cm-disc 43`:
```
./rsa_single -n 91982984654412298918905100667093043234916389105208833040709639508773652128538386023015487388659716487603461878610876776626504190644167683365520501112611688367330270792623674565452046825518198937965209215150436486498446004121478350269720860943418316052259143174980621393390145101255733850628736444988025154417 --attack factor_cm --cm-disc 43
```

### Prime factor recovery

Not an attack, but a useful tool:
if you know the modulus $n$, the public exponent $e$ and the private exponent $d$, then the prime factors $p$ and $q$ can be recovered efficiently.

It is only needed to provide as inputs:
```
./rsa_single -n <modulus> -e <public exponent> -d <private exponent>
```
Examples of values:
```
n = 22696111367870921015552731040448897566507944375931042540652706299121991614888334531171387175658733966997244143173157890392907827477367346607713916863796171326177520101713725914087688865476228551315082805706679478749266289221359032140781888933984489480794719967889033692566354693669616972516160753562320211223639257992396545436008184792442951808306948737032298532772875790800830881955773307644355549794036541111626528788884114173153978251774810938317616181492743832898279751396217437933976006825501587968208924746679998381237046921353037141943546390048021002481176265400867233346941684414591228996327766412084634266611
e = 27932651861055140386060965899334690004357850158789164016508259139053280040653073648731056771182337017127266259577204953090950812323902334004839247713062439372028611574575793662270571197275087876685181524967715870228936570428857583442344598640705649033130027339880345239482024764484246436327131202225731332581706313017387732923583210508166646515840651292967687626044324129215248799147723340753812866889280403575278251305822566242044377666464199468143194611331116477413854892802185919604407151905325929727831131997832558375839687580051358939999804564585405477842195336689543772553611193407708850721517704119407337956067
d = 9943260508092169006587088199118425171830902190392606771645977773700478561757771084532321718580440346787261799763763575176818900275962586184600270181404730532861351224344137833968790269053363808019645436476299200911097100294331546734961159844513833424331914177069662523934866883837779741344122073071827971036243564609786681321425120710639043927525925344297534197440286325362024398037668316964966038072009479726035209615785502474408875516344857171801005027179724022401482579109116458528478663463477813806244159925653196521174426505792169331495659822688717349782581374707840313715567702373979060300408163034228476296939
```

The factorization will be tried before the attacks.


## Partial key exposure attacks

These attacks are based on the [Coppersmith method](https://en.wikipedia.org/wiki/Coppersmith%27s_attack) using the PARI implementation [zncoppersmith](https://pari.math.u-bordeaux.fr/dochtml/html-stable/Arithmetic_functions.html#zncoppersmith).

### Prime factor partially known

The program is `rsa_partial_p`.

When a prime factor has the form $p_1m + p_0$ with $m$ known and either $p_0$ or $p_1$ is known, then it is possible to factorize the modulus if the unknown part is small enough (the unknown part must be less than the square root of the prime).

The classic cases are the least significant bits or most significant bits known, *e.g.*, $p = p_12^\ell + p_0$ where $p_0$ are the least significant bits and $p_1$ the most significant bits.

There are at least three arguments to provide on the command line:
- `-n`: the modulus
- `-m` or `-l`: the value $m$, with `-l` for $\ell$ as a shortcut to $m = 2^\ell$
- `--p0` or `--p1`: the value for $p_0$ or $p_1$


For example on a 2048-bit modulus where the lowest 550 bits of a prime factor are known:
```
./rsa_partial_p -n 13119193403816830793990020105152355901982760614873801464375917678025065739048003185494636371313780011831857152214217440782567145902927096934200780901175561902275466703798808659104617244144087431162940126703538094588037639518061967197788194738169456298819215654435302715537959258539871378266536694497224712249234811175783150844691251663192627203817117235161385427808717762093868131881458111684622575119829119366827364733230579221429792368278601241159791950119900718772179113375924119481268456663034285003109342081016561661599563375935622560670966330625247545939543766802563471823385112319808816272261823379448025873739 --p0 2934420658750547736814120888133950713470514375174395709298098829761854015306805148723137182826988004471491598165216520723737649898321094828333493293605610787003913429 -l 550
```


### Private exponent partially known

The program is `rsa_partial_d`, and it is another example of an application of Coppersmith method:
the Boneh-Durfee-Frankel attack.

When a private exponent has its least significant bits leaked, we can construct candidates for the least significant bits of the prime factors, then we can apply Coppersmith method exactly as in the [previous section](#prime-factor-partially-known).

There are at least four arguments to provide on the command line:
- `-n`: the modulus
- `-e`: the public exponent
- `-d`: the known least significant bits of the private exponent
- `-l`: the number of known least significant bits of the private exponent

There exists an integer $k$ such that $$ed = 1 + k(N - (p + q) + 1),$$ and the program will run through all possible values for $k$ with $1 \leq k < e$ so the public exponent must not be too large.
Optional arguments can be provided to reduce the search in a specific range:
- `--kstart`: starting value
- `--kend`: last value (excluded)

The verbose flag `-v` can be used to monitor the progress.

An example is given below with a 2048-bit modulus, $e = 17$, and 600 bits known of the private exponent:
```
./rsa_partial_d -n 26040126172475431783119902015090731414377196818904461477915067398362324203430504300064697476276490482910709172856734842777823393715774163080956922775258209631320059736915243325908337992848925227528713970604804361028163083473491758558237913430210064571033557386194556617580745915249782527149592529203621024073121710029126239326691968974178503820002033481133673641132882571832935691676591947237052776386939275914378577302754834310018939728604069978210275845400180924628741621425451756897987070800545557156434400696504014322952987634929923075809745269196613425970644434351288933067038618104855247833740686037049425950387 -e 17 -d 2116566865880123390785925860105005109406660379159536955743559155000405313839763902185871384849793489362656587401388986042928766266658948772192503667447622443725178287482722554889745 -l 600
```

In the case where the prime factors have a few least significant bits in common, the attack can be run **much faster**.
Indeed, it is possible to detect which value of $k$ is the most probable without having to apply Coppersmith's method.

The argument to run this detection is:
- `--kdetect <val>`: the value that follows indicates the minimal number of shared least significant bits to detect.
If this value is too low (less than 8), then there will be too many results printed, but the highest number of shared least significants bits and the value $k$ will be printed at the end.

An example is given below for a 2048-bit modulus, 600 bits of $d$, and 65537 for the public exponent.
We use the argument `--kdetect 10`.

```
./rsa_partial_d -n 22140601372084101424584451749639062840824198866941211550814665183338509032591847517467149269739548865470079296417017641765230227525595034643597525726473791413708823600755906851528872590079401923586337314805362785846248265700185997302598253360098066176547898459646940019551247636807708295260786386630879551779164980898112831366931782726773766660552476183828621456488085142110436814633432617832495524305078405398104902928307436171780994649214182139384472664422242476541205411288462399282145681597741099595369770559169587903910528982726655592104994350901400056890770494110024557861991523102652969964449149900532893877753 -e 65537 -d 2712688616761009854225717811156762420498585984744518098414682617846265651926397659459226586051236587509163814779757818160099911442357698000668348146020447792814466430263861713608161 -l 600 --kdetect 10
```

The results appear almost immediately:
```
[x] k = 10542
    Number of shared lsb: 10
    p mod 2^10 is one of the four values:
    * 75
    * 437
    * 587
    * 949
[x] k = 43310
    Number of shared lsb: 20
    p mod 2^20 is one of the four values:
    * 71605
    * 452683
    * 595893
    * 976971
[x] Number of k candidates: 2
    Highest number of lsb: 20 for k = 43310
```

The case $k = 43310$ seems interesting: it is detected that the primes share their 20 least significant bits if $k$ is correct.
It is high enough to be suspicious that it is not random, so we can run the attack using `--kstart 43310`:

```
./rsa_partial_d -n 22140601372084101424584451749639062840824198866941211550814665183338509032591847517467149269739548865470079296417017641765230227525595034643597525726473791413708823600755906851528872590079401923586337314805362785846248265700185997302598253360098066176547898459646940019551247636807708295260786386630879551779164980898112831366931782726773766660552476183828621456488085142110436814633432617832495524305078405398104902928307436171780994649214182139384472664422242476541205411288462399282145681597741099595369770559169587903910528982726655592104994350901400056890770494110024557861991523102652969964449149900532893877753 -e 65537 -d 2712688616761009854225717811156762420498585984744518098414682617846265651926397659459226586051236587509163814779757818160099911442357698000668348146020447792814466430263861713608161 -l 600 --kstart 43310 -v
```

The guess is correct: the factorization is instanteneous as we can see below (with the verbose flag):
```
[!] Modulus bit length: 2048
[x] Test k = 43310 (max: 65536)
    -> If k is correct, p and q have their 20 least significant bits in common.
    -> Trying Coppersmith with p mod (65537*2^579), a 596-bit integer.
p = 169593677653850406896385430998609396859727991212394977450558111622001294971901922578016142041311790279592522105520303820131065802976816492598799693999522439657483387291576120599286531252930041526940462924878679108765099541218827204928001081323822823228600605436374349107428199502683855909616154450700242327477
q = 130550865329273832587305356566040419694670950328095879259110965705886063868168807925474196497490110373477013909904101487953920320000398659381396593002529177787808824727969063679587298925129484667560418638632171487148460289570395734103809815723341404732371939864093864214259570447124335262693320903626545239989
```

## Changelog

- Version 0.1
  - Fixes two mistakes from initial commits


## License

This program is free software and is distributed under the [GPLv3 License](./LICENSE).

```
rsatools, a set of cryptanalysis tools against RSA
Copyright (C) 2022 A. Russon

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
