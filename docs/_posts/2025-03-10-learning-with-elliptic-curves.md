---
layout: default
title: "Learning with Elliptic Curves (HelseCTF 2025)"
date: 2025-03-09 10:00:00 -0000
categories: writeups
tags: [Elliptic Curves, ECDLP, LWE, Lattice]
---


##### Challenge overview

In this CTF challenge, we are given the following python source code, along with the output.txt

```python
from sage.all import *
from random import randint
from hemmelig import flagg

p = 39761755302725183918693591729206126391094688519137850931996389197052105934335057950945885109127019315116708698582684135940731
a = 37470413545164594923241940723449977961814431955261347161951289533994732796785078955994373335971437954627235171462939970255523
b = 33862474237826219764283873646917712191796653587975971730267794592641857158089029148517141460472220490573591617494610494543421 

gf = GF(p)
E = EllipticCurve(gf, [a, b])
G = E.gen(0)
print(f"G = {G.xy()}")

offentlig_nøkkel = [randint(1, p) * G for _ in flagg]
print(f"offentlig_nøkkel = {[P.xy() for P in offentlig_nøkkel]}")
hemmelighet = [ord(c) for c in flagg]
error = randint(-1000, 1000) * G

resultat = sum(o * h for o, h in zip(offentlig_nøkkel, hemmelighet)) + error
print(f"resultat = {resultat.xy()}")
```

This is a Learning with Errors type of challenge, but based on elliptic curve arithmetic. We are given the public key consisting of a random point on the curve $E$ for each character in the flag. We are also given point $resultat$ from the LWE-looking equation. The encryption is essentially:

$$
\large resultat = \left( \sum_{i=0}^{n-1} o_{i}\cdot h_{i} \right) + error
$$

But since $h_{i}$ is just a small integer value, and each point in the public key is computed as

$$
\large r_{i}\cdot G
$$

Where $r_{i}$ is a random integer, we can rewrite as

$$
\large resultat = \left( \sum_{i=0}^{n-1} r_{i}\cdot h_{i} + e\right) \cdot G  
$$

This means we could potentially compute the discrete logarithm for $resultat$ to unwrap the elliptic curve arithmetic back into an integer equation. We can also compute the discrete logarithm of the public key points $o_{i}$ with respect to $G$ to recover $r_{i}$, which would leave us with an equation of the form

$$
\large X = \sum_{i=0}^{n-1} r_{i}\cdot h_{i}+e \mod order(G)
$$

The equation is a modular linear equation with small unknowns. We can utilize this solver: https://github.com/nneonneo/pwn-stuff/blob/main/math/solvelinmod.py, but we need to make some preparations first.

Normally, the discrete logarithm problem can be quite tricky to solve. However, in our case, the order of curve $E$ is very smooth:

```python
sage: factor(E.order())
2^2 * 7 * 11 * 13 * 19 * 31 * 59 * 67 * 79 * 101 * 103 * 139 * 179 * 233 * 241 * 269 * 271 * 283^4 * 419 * 431 * 439 * 463 * 509 * 563 * 571 * 617^2 * 641^3 * 659 * 691 * 719 * 733^2 * 739 * 743^2 * 761 * 773 * 797 * 821 * 823^2 * 829 * 929 * 937 * 977
```

meaning it is easy to solve with something like Pohlig-Hellman. 

```python
print("Computing discrete logs for public keys ...")
r_values = []
for P in offentlig_nøkkel:
	r = discrete_log(P, G, operation="+")
	r_values.append(r)

order = G.order()

X = discrete_log(resultat, G, operation="+")
```

We can now begin to set up the equation for $X$ where we wish to solve for the unknown flag characters $h_{i}$.
Firstly, we must define some variables to represent the unknowns:

```python
n = len(r_values)
flag_vars = [var(f"x{i}") for i in range(n)]
e_var = var("e")
```

We can now express our equation as

```python
equation = (sum(r_values[i] * flag_vars[i] for i in range(n)) + e_var == X, order)
```

Lastly, we need to define the bounds of possible values for the unknowns. We know $h_{i}$ are the numerical ascii codes for the flag characters, which means the possible values are between $0, 256$ (we could in reality assume that its between $32, 126$ for printable characters). And from the source code, we already know the error value $e$ is between $-1000, 1000$.

```python
bounds = {flag_vars[i]: (0, 256) for i in range(n)}
bounds[e_var] = (-1000, 0, 1000) # (min, expected, max)
```

And with everything set up, we can now utilize the linmod solver after it has been imported:

```python
print("Solving modular linear equation using lattice reduction...")
solution = solve_linear_mod([equation], bounds)
recovered_flag = ''.join(chr(solution[flag_vars[i]]) for i in range(n))
print(f"Recovered flag: {recovered_flag}")
#Recovered flag: helsectf{Ell1pt15k3_kurv3r_3r_l1vet!}
```

##### Solve.sage 

```python
from collections.abc import Sequence
import math
import operator
from typing import List, Tuple

from sage.all import ZZ, gcd, matrix, prod, var

# Solver from: https://github.com/nneonneo/pwn-stuff/blob/main/math/solvelinmod.py
def _process_linear_equations(equations, vars, guesses) -> List[Tuple[List[int], int, int]]:
    result = []

    for rel, m in equations:
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError(f"relation {rel}: not an equality relation")

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in vars:
                raise ValueError(f"relation {rel}: variable {var} is not bounded")

        # Fill in eqns block of B
        coeffs = []
        for var in vars:
            if expr.degree(var) >= 2:
                raise ValueError(f"relation {rel}: equation is not linear in {var}")
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError(f"relation {rel}: coefficient of {var} is not constant (equation is not linear)")
            if not coeff.is_integer():
                raise ValueError(f"relation {rel}: coefficient of {var} is not an integer")

            coeff = int(coeff)
            if m:
                coeff %= m
            coeffs.append(coeff)

        # Shift variables towards their guesses to reduce the (expected) length of the solution vector
        const = expr.subs({var: guesses[var] for var in vars})
        if not const.is_constant():
            raise ValueError(f"relation {rel}: failed to extract constant")
        if not const.is_integer():
            raise ValueError(f"relation {rel}: constant is not integer")

        const = int(const)
        if m:
            const %= m

        result.append((coeffs, const, m))

    return result


def solve_linear_mod(equations, bounds, verbose=False, use_flatter=False, **lll_args):
    """Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
        M may be None to indicate that the equation is not modular.
    bounds: A dictionary of {var: B} entries, where var is a variable and B is the bounds on that variable.
        Bounds may be specified in one of three ways:
        - A single integer X: Variable is assumed to be uniformly distributed in [0, X] with an expected value of X/2.
        - A tuple of integers (X, Y): Variable is assumed to be uniformly distributed in [X, Y] with an expected value of (X + Y)/2.
        - A tuple of integers (X, E, Y): Variable is assumed to be bounded within [X, Y] with an expected value of E.
        All variables used in the equations must be bounded.
    verbose: set to True to enable additional output
    use_flatter: set to True to use [flatter](https://github.com/keeganryan/flatter), which is much faster
    lll_args: Additional arguments passed to LLL, for advanced usage.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds tighter and try again.

    Tip: if you get an unwanted solution, try setting the expected values to that solution to force this function
    to produce a different solution.

    Tip: if your bounds are loose and you just want small solutions, set the expected values to zero for all
    loosely-bounded variables.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}

    >>> x,y = var('x,y')
    >>> # we can also solve homogenous equations, provided the guesses are zeroed
    >>> solve_linear_mod([(2*x + 5*y == 0, 1337)], {x: 5, y: 5}, guesses={x: 0, y: 0})
    {x: 5, y: -2}
    """

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).
    # Scaling factors are configured to generally push the smallest vectors to have zeros for the relations, and to
    # scale disparate variables to approximately the same base.

    vars = list(bounds)
    guesses = {}
    var_scale = {}
    for var in vars:
        bound = bounds[var]
        if isinstance(bound, (tuple, list)):
            if len(bound) == 2:
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // 2 + xmin
            elif len(bound) == 3:
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = 0
            xmax = int(bound)
            guess = xmax // 2
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, 1)
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations if m)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != 0 for coeffs, const, m in equation_coeffs)
    mod_count = sum(1 for coeffs, const, m in equation_coeffs if m)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += 1
    B = matrix(ZZ, mod_count + NV, NR + NV)

    # B format (rows are the basis for the lattice):
    # [ mods:NRxNR 0
    #   eqns:NVxNR vars:NVxNV ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)
    # mods and vars are diagonal, so this matrix is lower triangular.

    # Compute maximum scale factor over all variables
    S = max(var_scale.values())

    # Compute equation scale such that the bounded solution vector (equation columns all zero)
    # will be shorter than any vector that has a nonzero equation column
    eqS = S << (NR + NV + 1)
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + 1
    col_scales = []

    mi = 0
    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[mod_count + vi, ri] = c
        if is_inhom:
            B[mod_count + NV - 1, ri] = const
        if m:
            B[mi, ri] = m
            mi += 1
        col_scales.append(eqS)

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[mod_count + vi, NR + vi] = 1

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[mod_count + NV - 1, -1] = 1

    if verbose:
        print("verbose: scaling shifts:", [math.log2(int(s)) for s in col_scales])
        print("verbose: matrix dimensions:", B.dimensions())
        print("verbose: unscaled matrix before:")
        print(B.n())

    for i, s in enumerate(col_scales):
        B[:, i] *= s
    if use_flatter:
        from re import findall
        from subprocess import check_output

        # compile https://github.com/keeganryan/flatter and put it in $PATH
        z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in B) + "]]"
        ret = check_output(["flatter"], input=z.encode())
        B = matrix(B.nrows(), B.ncols(), map(int, findall(b"-?\\d+", ret)))
    else:
        B = B.LLL(**lll_args)
    for i, s in enumerate(col_scales):
        B[:, i] /= s

    # Negate rows for more readable output
    for i in range(B.nrows()):
        if sum(x < 0 for x in B[i, :]) > sum(x > 0 for x in B[i, :]):
            B[i, :] *= -1
        if is_inhom and B[i, -1] < 0:
            B[i, :] *= -1

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != 0 for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-1] != 1:
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != 0},
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res


p = 39761755302725183918693591729206126391094688519137850931996389197052105934335057950945885109127019315116708698582684135940731
a = 37470413545164594923241940723449977961814431955261347161951289533994732796785078955994373335971437954627235171462939970255523
b = 33862474237826219764283873646917712191796653587975971730267794592641857158089029148517141460472220490573591617494610494543421 

gf = GF(p)
E = EllipticCurve(gf, [a, b])
G = E.gen(0)
print("G =", G.xy())

offentlig_nokkel_coords = [
(19344995651025956194741672391212032148363490396937400401146819955355580393176808369173184320136313448134647998758831966754736,34020826004970877240134787872651656341416368729440458356772758698852519328204528888078873163885699991764853721479123610703057),(38966172409616242154304141143709898301034470122461722607712942742033687783643301247009025399729745022556064024850518869451975,5981020799362018596735936290285344387211688865092193941491931169619830103374376973760714068642118719362457727239510914584312), (7012878627760257841132118070607478265284965240349652309759124191322573986096551843751246689024934516739883838453379849725751, 21649710842932323285463795978767807324556917210964041962739790237236275762823921746606063379573395895459130209397906892095198),(16507820273786900224618748750477369369775435705316765856004067873105139579722596955551099931764203698774088259217970865323799,9928713485305875739506130889554325411729009153463022555918280976553112545014442785040986950316547911895874494514074098917894), (14055726663591292873961297946052533592325700065779495995571239086780922293043115049640092519426435728577412970964860502584449,30485748320816380831514092554721453382052900140209991279839693184940939803544687454557399278030782153436443843797878162131674),(19284533584902441535038251888281949359237393762112655572077569950661307649081647225051558606183700516352557183155082396507339,31789499814834902156506651897418657730851979924342092149083494301240879566203258318324279812405062325758883084316388028234579),(28563743478892127827438135408124657877593631512851235793560586090530615354590467727997486849059095488933932291824423145715989,25665200201155002744035128647945633598163319971421639263108985895408409856469875694440510114104190480548047704288193118501977),(8237411227822132038206373512614285405591981546461995832779339333592557055834188155984551094441805050462771868300394115224375, 9885852244328856561608785982938660796665507504121412998798975798901881787628711681405954967253476772481210173364953121589569), (21181985550811301835779112200376346636025418520808320184931262305958073757014994270429006350952950798310763860866304539428929,6884701502844069177625971506999045981345995595705569692948922952369734751204260690491272933693975446873824249524309618970166), (6788587008462034943410368611241496145015831006919232554367954799108989568960420306961801801625921628580097121258960350700616, 7635783031494681408229331516727445970079910973779703487539674574209624228670655658114668541055090475326537403610663421717055), (34698918716321067804863000464018663206020680011298961086526003259750622996268085071858633541035040445940040693707640153655632,16384492064938169922484926227544844042674774692541434008770082166704569520085415713559690586140748815044546227319134849083937),(10658974785580326054433035059311986417475084708116100695444229265131486566672126986110855036056235411708879953276778915747801, 512033780990944074185563748626730709761992606831859714133668839103428371946017012458822632270307898211602256126273987669132), (8622011872253081660673091782773585822060637051075312656402567659535855409821932333482382411981983992572035293537198471300443, 39022515826644233788881586619347250212977673395132189646832370764675062592750514668680322547648802196304673254653571721291831), (733746435861052343265423986364461942348676907044568071574314976256865094935712580652635360676426823887304743127942655669737, 35699658584837934841721507175186736204106629480007391268786882614665034436247870540906673672955477842345407758711255421701272),(37939426890774994620687639386442335504804214910213475108653073835175095782887561413623491816689117769855921083421601000351221,35484662781609586835666968283377268002573421586505838429006735486351151941782347671265691433508246152630679857286434611823446),(27671434794626920166815769310586909573137141964976057656198980121930015805040405450922076489265137388163898643646828570297312,15804008446744328534974710571663042229605689599724078001882369669149290404107074338305844058792073815442376248853911841614426),(20950482645513610873765064128356556647853383897087887862635288029551420919838051885419671413603809323953440287910086578994272,13179730620551517421814470850730448699505360331488970430430199559692709864311666620597196650579997342340297429683266669665805),(38209802766336036826548158011858091566763499319755339954976644987497178193491031815701219011999258731732565706983754522742860,32075952411759489640105226466556224741572861015631622764015731585347955580393913886424341362200247972419249692718256292405497),(29715879263362133992147038430203964295629513055492327942093840791136536190075611961658831084719071107836887811583662865879707,13919539779082633178483137734805867250894605291219091326819707826267111628567784026617883661947346871050484166323317372092681),(17596448059924478922611374900453610553302087678439808939152903825727511660677906979887680120862442594782190195990376480227247,18848917550521531970852496369038841222855249240611234505174458309342823960300837116527482677611242707548544929064942808521326),(11694674951617050896888126743690058647375337519424427182693314257629019803360357415031340224437750579664116587883003716347322,23769034524399304221482377572880603810420827986816819410647124240381458717464137504868299950648504922208277820779862263213253),(28044352636044165142531892612483278790309014066998469173880740484234864937824324353622678955699284335850641632696218607711105,36852342519447641222459786922480459165554935411917926715070142361516598240249543218059044962301159233451421107516861058931350),(39472716548612380290361977865584209019941773021001278034808705016371847732706310749561371415767551848024898140778002489761104,13778771389568946804361056265311684945284062484739422530826916480764877337518958508982589095578772377611594544422376483705189),(12383735787832868736512166373154971015290898726854325082693549282798933504244296605160216975903246810620642146814345310554245,14606252906250500651763421535808607189949773824275233075682901325789088277988476921580364063054361211058708760529784757163069),(7911163544792784677994220674429320832525623274395272821492773307062011009307739889205201720778512712202950737090638605306941, 32328838849120475224173379425480516068696470208616385098516834929939549599336938286263319475085712307078669689264043940279300),(6806084376297874363978666332947512148582907530266444061137669650799184257952980294236356891605898752326730504084259266607078, 4086053235856464049299978367263407974062293925257987675966363058200510421805899650679492916373893962060529530866829744661115), (20068421201757796406821504148184756417915558249894999425509689063181453172284226606798981021385347488384527499616803388564798,10471301146159400545932616687757275132945443353048424290724629816042012731619948044876834966798469450294545018272842518767039),(37732339642517665660573396789456436211371585579156819026373871223024196528579359580573460397737420382889142185220947626429988,35588564732766799911411770707054827045426121818169585798083508100212146760878114879993716618460747691986999221885780988213939),(18994922082342729210669842066574295649621438440922345176100372319975853401945330951612964095074112154449538291135263645795633,7421835481723385629627683542845775174176654429284456417903254652848254644501526524277397274456927128375951677872783186544197), (10936179747633490187048811205659632385493108913888571448351520692827861401235904055783909618959144801043869111517493064450813,37767515592460780812692994627273499472840828310356287804193220268370806467963587115872332370607004725228518423275190521909036),(15578363357360720656604318751099363826610190567191944249530552187368108247234937882283894395989015950625087477601990604613568,12944764605838608945255892796385860090328827583817839716418744552699643658761977975421689813669953770928326326679477989760425),(18465487551066678587591230816929918491636227429489142712426400860471604878959497312492289805250369784518246291043516743718314,33048932538804853453137676161648323915507524602563070414028513687897002445778522892502931139172408593517572601654502257710179),(36405447831709193796097960326620635017451602614074697050898363305471353306230658731010486585219737953570079593165399424640077,39408299074343594603359628294024899354312805473493079470807758263096873347563725962734813169017704613381036169912740705802415),(31489959783721349126832583793042849991821734712454827062803050435506164238311383809821966356053124230213468581001961871705240,1370610624414638548357272623280330236940111440345356060614790482301844799622501923372464196490616842945705405162689484422131), (38410418347480905434105603211519555470978675975416499460761655754318826230236231759067316884038352846297919716523834617388809,38373076908014641207743595020405645972279538291511910579173338937672642301553739809924261109302942930372828119645211569180371),(18699249088920525263336529579250720339651996780233633707443800456666031211347230017240747302897271985757953958425270369197271,15810499777345670198178975014724801539468143573738090921792268760133300634100091531087694924391974063121939953084474417068575),(26959780058637657932043291551863273749284276382492090808843948794474433894425495846938331234168041540969970436897968026924422, 1575063286522455595288872157965487016380397319130447521930183949162108900735380591336731890417444500695552903110119195898094)]

offentlig_nøkkel = [E(x, y) for (x, y) in offentlig_nokkel_coords]
resultat = E(20651818137470466933477728509072550437756475330872536030571099768051457046843355623709212804930440099044049040144879241690983,35600016854460355091451342763877862314510764810503386770058531389353025412814465374425619239887352848890007571085094884466047)

print("Computing discrete logs for public keys ...")
r_values = []
for P in offentlig_nøkkel:
	r = discrete_log(P, G, operation="+")
	r_values.append(r)

order = G.order()

X = discrete_log(resultat, G, operation="+")

n = len(r_values)
flag_vars = [var(f"x{i}") for i in range(n)]
e_var = var("e")

equation = (sum(r_values[i] * flag_vars[i] for i in range(n)) + e_var == X, order)
bounds = {flag_vars[i]: (0, 256) for i in range(n)}
bounds[e_var] = (-1000, 0, 1000)

print("Solving modular linear equation using lattice reduction...")
solution = solve_linear_mod([equation], bounds)
recovered_flag = ''.join(chr(solution[flag_vars[i]]) for i in range(n))
print(f"Recovered flag: {recovered_flag}")
```

Flag: `helsectf{Ell1pt15k3_kurv3r_3r_l1vet!}`