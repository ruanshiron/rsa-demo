String.prototype.encode = function (rsa) {
    let n = rsa.n, e=rsa.e, result = ""
    let M = this.toNumber()
    let mBinary = M.toString(2)

    let bits = Math.floor(Math.log2(n-1))
    
    if (mBinary.length <= bits) {
        let C = Number(powMod(BigInt(M), BigInt(e), BigInt(n)))
        result = C.toWord()
    } else {
        let count = (mBinary.length % bits == 0) ? Math.floor(mBinary.length / bits) : Math.floor(mBinary.length / bits + 1)

        let segment = []

        if (mBinary.length % bits == 0) {
            for (let i = 0; i < count; i++) {
                segment[i] = mBinary.substring(i*bits, (i+1)*bits)
            }
        } else {
            segment[0] = mBinary.substring(0, mBinary.length % bits)
            for (let i = 0; i < count; i++) {
                segment[i] = mBinary.substring(mBinary.length % bits + (i - 1) * bits, mBinary.length % bits + i * bits)
            }
        }
        

        let listDecimal = [], listBinary = [],C = [] 
        listDecimal.length = count
        listBinary.length = count
        C.length = count
        

        for (let i = 0; i < count; i++) {
            listDecimal[i] = parseInt(segment[i], 2)            
            C[i] = Number(powMod(BigInt(listDecimal[i]), BigInt(e), BigInt(n)))
            listBinary[i] = C[i].toString(2)
            if (listBinary[i].length < bits + 1) {
                let repeat = []
                repeat.length = bits + 1 - listBinary[i].length
                repeat.fill(0)
                listBinary[i] = repeat.join("") + listBinary[i]
            }
            
            result += listBinary[i]
            
        }

        let resultDecimal = parseInt(result, 2)
        result = resultDecimal.toWord()
    }
    
    return result
}

String.prototype.decode = function (rsa) {
    let n = rsa.n, d = rsa.d
    let result = "", C = this.toNumber()
    let cBinary = C.toString(2)

    let bits = Math.floor(Math.log2(n-1))
    
    if (cBinary.length <= bits) {
        let M = Number(powMod(BigInt(C), BigInt(d), BigInt(n)))

        result = M.toWord()
    } else {
        let count = (cBinary.length % (bits + 1) == 0) ? Math.floor(cBinary.length / (bits + 1)) : Math.floor(cBinary.length / (bits + 1) + 1)
        
        let segment = []
        

        if (cBinary.length % (bits + 1) == 0) {
            for (let i = 0; i < count; i++) {
                segment[i] = cBinary.substring(i*(bits + 1), (i+1)*(bits + 1))
            }
        } else {
            segment[0] = cBinary.substring(0, cBinary.length % (bits + 1))
            for (let i = 0; i < count; i++) {
                segment[i] = cBinary.substring(cBinary.length % (bits + 1) + (i - 1) * (bits + 1), cBinary.length % (bits + 1) + i * (bits + 1))
            }
        }

        let listDecimal = [], listBinary = [],M = [] 
        listDecimal.length = count
        listBinary.length = count
        M.length = count

        for (let i = 0; i < count; i++) {
            listDecimal[i] = parseInt(segment[i], 2)            
            M[i] = Number(powMod(BigInt(listDecimal[i]), BigInt(d), BigInt(n)))
            listBinary[i] = M[i].toString(2)
            if (listBinary[i].length < bits) {
                let repeat = []
                repeat.length = bits - listBinary[i].length
                repeat.fill(0)
                listBinary[i] = repeat.join("") + listBinary[i]
            }
            
            result += listBinary[i]
        }

        let resultDecimal = parseInt(result, 2)
        result = resultDecimal.toWord()
    
    }

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
    let rawSplit = raw.split(" ")
    let cipherSplit = []
    rawSplit.forEach(word => {
        cipherSplit.push(word.encode(rsa_public))
    });
    return cipherSplit.join(" ")
}

function decode(cipher, rsa_private) {
    let cipherSplit = cipher.split(" ")
    let rawSplit = []
    cipherSplit.forEach(word => {
        rawSplit.push(word.decode(rsa_private))
    });
    return rawSplit.join(" ")
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

console.log(encode("ngoc", rsa_public))
console.log(decode("uyrwt", rsa_private))







