String.prototype.toArray = function (rsa_n) {
    let result = []    

    this.trim().split("").forEach(c => {
        if (c == " " || result[result.length - 1] == " " || result.length == 0) 
            result.push(c)
        else if ((result[result.length-1]+c).toNumber() < rsa_n)
            result[result.length - 1] = result[result.length - 1] + c
        else result.push(c)
    })

    return result
}


String.prototype.toNumber = function (n) {
    if (n == null) n = 27

    let l = this.length - 1
    let result = 0
    for (let i = 0; i < this.length; i++) {
        const c = this.charAt(i);

        let temp = n;
        temp = Math.pow(temp, l)
        temp = temp * (c.charCodeAt(0) - 96)
        result = result + temp
        l--
    }

    return result;
}

Number.prototype.toWord = function (n) {
    let number = new Number(this)


    if (n == null) n = 27
    let word = ""
    let temp

    while (number > 0) {
        temp = number % n
        word += String.fromCharCode(temp + 96)
        number = Math.floor(number / 27)
    }

    return word.split("").reverse().join("")
}

function powMod(base, exp, mod) {
    if (exp == 0n) return 1n;
    if (exp % 2n == 0) {
        return powMod(base, (exp / 2n), mod) ** 2n % mod;
    }
    else {
        return (base * powMod(base, (exp - 1n), mod)) % mod;
    }
}

function encode(raw, rsa_public) {
    let rawSplit = raw.toArray(rsa_public.n)
    let cipherSplit = []
    rawSplit.forEach(word => {
        if (word != " ") {
            let temp = Number(powMod(BigInt(word.toNumber()), BigInt(rsa_public.e), BigInt(rsa_public.n))).toWord()
            cipherSplit.push(temp)
        } else {
            cipherSplit.push(word)
        }

    });
    return cipherSplit.join("")
}

function decode(cipher, rsa_private) {
    let cipherSplit = cipher.toArray(rsa_private.n)
    let rawSplit = []
    cipherSplit.forEach(word => {
        if (word != " ") {
            let temp = Number(powMod(BigInt(word.toNumber()), BigInt(rsa_private.d), BigInt(rsa_private.n))).toWord()
            rawSplit.push(temp)
        } else {
            rawSplit.push(word)
        }
    });
    return rawSplit.join("")
}

function privateKey(rsa_public) {
    // Tìm p & q
    let n = rsa_public.n
    let e = rsa_public.e
    let sqrtN = Math.floor(Math.sqrt(n))
    let p = sqrtN, q

    while (p != 1) {
        if (n % p == 0) break
        p = p - 1
    }

    q = Math.floor(n / p)

    // m = (p-1) * (q-1);
    let m = (p - 1) * (q - 1)

    let xa = 1, ya = 0, xb = 0, yb = 1, temp = m

    while (m != 0) {
        let z = Math.floor(e / m)
        let r = e % m
        e = m;
        m = r;
        let xr = xa - z * xb
        let yr = ya - z * yb
        xa = xb;
        ya = yb;
        xb = xr;
        yb = yr;
    }

    if (xa < 0) {
        xa = xa + temp
    }

    return {p, q, d: xa, m: temp }

}

function cryptanalysis(cipher, rsa) {
    rsa = {
        ...rsa,
        ...privateKey(rsa)
    }
    return { raw: decode(cipher, rsa), rsa }
}

const rsa_public = {
    e: 17,
    n: 3233
}

const rsa_private = {
    n: 3233,
    d: 2753
}








