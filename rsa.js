BigInt.prototype.log2 = function () {
    return (this  > 1n) ? (1n + (this/2n).log2()) : 0n
}

String.prototype.encode = function (rsa) {    
    let n = BigInt(rsa.n), e = BigInt(rsa.e), result = ""
    let M = this.toBigInt()
    let mBinary = M.toString(2)

    

    let bits = (n-1n).log2()

    let l_mBinary = BigInt(mBinary.length)
    
    if (l_mBinary <= bits) {
        let C = powMod(M, e, n)        
        console.log(C);
        
        result = C.toWord()        
    } else {
        let count = (l_mBinary % bits == 0n) ? (l_mBinary / bits) : (l_mBinary / bits + 1n)

        let segment = []

        if (l_mBinary % bits == 0n) {
            for (let i = 0n; i < count; i++) {
                segment[i] = mBinary.substring(Number(i*bits), Number((i+1n)*bits))
            }
        } else {
            segment[0] = mBinary.substring(0, Number(l_mBinary % bits))
            for (let i = 0n; i < count; i++) {
                segment[i] = mBinary.substring(Number(l_mBinary % bits + (i - 1n) * bits), Number(l_mBinary % bits + i * bits))
            }
        }
        

        let listDecimal = [], listBinary = [],C = [] 
        listDecimal.length = Number(count)
        listBinary.length = Number(count)
        C.length = Number(count)
                

        for (let i = 0n; i < count; i++) {
            listDecimal[i] = BigInt("0b"+segment[i])            
            C[i] = powMod(listDecimal[i], e, n)
            listBinary[i] = C[i].toString(2)
            
            let list_l = BigInt(listBinary[i].length)
            if (list_l < bits + 1n) {
                let repeat = []
                repeat.length = Number(bits + 1n - list_l)
                repeat.fill(0)
                listBinary[i] = repeat.join("") + listBinary[i]
            }
            result += listBinary[i]
        }
        
        let resultDecimal = BigInt("0b"+result)
        
        result = resultDecimal.toWord()
    }
    
    return result
}

String.prototype.decode = function (rsa) {
    let n = BigInt(rsa.n), d = BigInt(rsa.d)    
    
    let result = "", C = this.toBigInt()
    let cBinary = C.toString(2)

    let bits = (n-1n).log2()


    let l_cBinary = BigInt(cBinary.length)
    
    
    if (l_cBinary <= bits) {
        let M = powMod(C, d, n)
        
        result = M.toWord()
    } else {
        let count = (l_cBinary % (bits + 1n) == 0n) ? (l_cBinary / (bits + 1n)) : (l_cBinary / (bits + 1n) + 1n)
        
        let segment = []
        

        if (l_cBinary % (bits + 1n) == 0n) {
            for (let i = 0n; i < count; i++) {
                segment[i] = cBinary.substring(Number(i*(bits + 1n)), Number((i+1n)*(bits + 1n)))
            }
        } else {
            segment[0] = cBinary.substring(0, Number(l_cBinary % (bits + 1n)))
            for (let i = 0n; i < count; i++) {
                segment[i] = cBinary.substring(Number(l_cBinary % (bits + 1n) + (i - 1n) * (bits + 1n)), Number(l_cBinary % (bits + 1n) + i * (bits + 1n)))
            }
        }

        let listDecimal = [], listBinary = [],M = [] 
        listDecimal.length = Number(count)
        listBinary.length = Number(count)
        M.length = Number(count)

        for (let i = 0n; i < count; i++) {
            listDecimal[i] = BigInt("0b"+segment[i])            
            M[i] = powMod(listDecimal[i], d, n)
            listBinary[i] = M[i].toString(2)

            let list_l = BigInt(listBinary[i].length)

            if (list_l < bits) {
                let repeat = []
                repeat.length = Number(bits - list_l)
                repeat.fill(0)
                listBinary[i] = repeat.join("") + listBinary[i]
            }
            
            result += listBinary[i]
        }

        let resultDecimal = BigInt("0b"+result)
        result = resultDecimal.toWord()
    
    }

    return result
}

String.prototype.toBigInt = function (n) {
    if (n==null) n = 94n
    n = BigInt(n)

    let l = BigInt(this.length - 1)
    let result = 0n
    for (let i = 0n; i < BigInt(this.length); i++) {
        const c = this.charAt(Number(i))
    
        let temp = n
        temp = temp ** l

        if (c == "~") 
            temp = 0n
        else 
            temp = temp * (BigInt(c.charCodeAt(0)) - 32n)
        result = result + temp
        l--        
    }

    return result
}

BigInt.prototype.toWord = function (n) {
    let number = BigInt(this)

    if (n==null) n = 94n 

    let word = ""
    let temp 

    while (number > 0) {
        temp = number%n + 32n
        if (temp == 32n) 
            temp = 126n;
        word += String.fromCharCode(Number(temp))
        number = number/n
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
        word = encodeURI(word)        
        cipherSplit.push(word.encode(rsa_public))
        
    });
    return cipherSplit.join(" ")
}

function decode(cipher, rsa_private) {
    let cipherSplit = cipher.split(" ")
    let rawSplit = []
    cipherSplit.forEach(word => {
        rawSplit.push(decodeURI(word.decode(rsa_private)))
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

console.log(cryptanalysis(encode("Nguyễn, QuangNgọc Thế Vinh", rsa_public), rsa_public));













