import java.math.BigInteger;
import java.util.Scanner;

public class RSA {

	static Scanner sc = new Scanner(System.in);

	public static void main(String[] args) {
		// Bộ thử RSA
		// p = 51343
		// q = 62981
		// n = p * q = 3233633483
		// m = (p-1) * (q-1) = 3233519160
		// Public key e = 65537
		// Private key d = 2854695593

		int choose = 0;
		do {
			System.out.println("****************************************");
			System.out.println("RSA MENU");
			System.out.println("1. Encryption");
			System.out.println("2. Cryptanalysis");
			System.out.println("0. Exit");
			System.out.println("****************************************");
			System.out.print("Choose function: ");
			choose = sc.nextInt();
			switch (choose) {
			case 1:
				encryption();
				break;
			case 2:
				cryptanalysis();
				break;
			}
		} while (choose != 0);
		System.out.println(wordToNumber("nghieng"));
		sc.close();
	}

	// Chức năng 1 mã hóa encryption
	static void encryption() {
		System.out.println("\n****************************************");
		System.out.println("Function 1: Encryption\n");

		System.out.print("Input n = ");
		sc.nextLine();
		String nString = sc.nextLine();
		BigInteger n = new BigInteger(nString);

		System.out.print("Input public key e = ");
		String eString = sc.nextLine();
		BigInteger e = new BigInteger(eString);

		// Nhập bản rõ để mã hóa
		System.out.println("Input plain text:");
		String plaintext = sc.nextLine();

		// Chuyển đổi bản rõ sang bản mã
		String ciphertext = new String();
		String[] list = plaintext.split(" ");
		for (int i = 0; i < list.length; i++) {
			ciphertext += encode(list[i], e, n) + " ";
		}
		ciphertext = ciphertext.trim();
		System.out.println("Cipher text:\n" + ciphertext);
		System.out.println("****************************************\n");
	}

	// Chức năng 2 giải khóa cryptanalysis
	static void cryptanalysis() {
		System.out.println("\n****************************************");
		System.out.println("Function 2: Cryptanalysis\n");

		System.out.print("Input n = ");
		sc.nextLine();
		String nString = sc.nextLine();
		BigInteger n = new BigInteger(nString);

		System.out.print("Input public key e = ");
		String eString = sc.nextLine();
		BigInteger e = new BigInteger(eString);

		// Phân tích bộ mã
		BigInteger d = privateKey(e, n);

		// Nhập bản mã để giải mã
		System.out.println("\nInput cipher text:");
		String ciphertext = sc.nextLine();

		// Chuyển đổi bản mã sang bản rõ
		String plaintext = new String();
		String[] list = ciphertext.split(" ");
		for (int i = 0; i < list.length; i++) {
			plaintext += decode(list[i], d, n) + " ";
		}
		plaintext = plaintext.trim();
		System.out.println("Plain text:\n" + plaintext);
		System.out.println("****************************************\n");
	}

	// Mã hóa một word
	static String encode(String word, BigInteger e, BigInteger n) {
		BigInteger M = wordToNumber(word); // Đổi word bản rõ sang số hệ 10
		BigInteger C = powMod(M, e, n); // Tính C = M^e mod n
		String result = numberToWord(C); // Đổi số hệ 10 sang word bản mã
		return result;
	}

	// Giải mã một word
	static String decode(String word, BigInteger d, BigInteger n) {
		BigInteger C = wordToNumber(word); // Đổi word bản mã sang số hệ 10
		BigInteger M = powMod(C, d, n); // Tính M = C^d mod n
		String result = numberToWord(M); // Đổi số hệ 10 sang word bản rõ
		return result;
	}

	// Phá khóa - Tìm private key d
	static BigInteger privateKey(BigInteger e, BigInteger n) {
		System.out.println("\nAnalysis results:");
		// Phân tích n = p * q
		BigInteger sqrtN = sqrt(n);
		BigInteger p = sqrtN, q;
		while (p.equals(BigInteger.ONE) == false) {
			if (n.mod(p).compareTo(BigInteger.ZERO) == 0)
				break;
			p = p.subtract(BigInteger.ONE);
		}
		q = n.divide(p);
		System.out.println("p = " + p);
		System.out.println("q = " + q);

		// m = (p-1) * (q-1);
		p = p.subtract(BigInteger.ONE);
		q = q.subtract(BigInteger.ONE);
		BigInteger m = p.multiply(q);
		System.out.println("m = (p-1) * (q-1) = " + m);
		BigInteger temp = m;

		// Thuật toán Euclid
		// Giải x * a + y * b = 1
		// d * e + y * m = 1
		BigInteger xa = BigInteger.ONE;
		BigInteger ya = BigInteger.ZERO;
		BigInteger xb = BigInteger.ZERO;
		BigInteger yb = BigInteger.ONE;

		while (m.equals(BigInteger.ZERO) == false) {
			BigInteger z = e.divide(m);
			BigInteger r = e.mod(m);
			e = m; // m = (p-1) * (q-1)
			m = r;
			BigInteger xr = xa.subtract(z.multiply(xb));
			BigInteger yr = ya.subtract(z.multiply(yb));
			xa = xb;
			ya = yb;
			xb = xr;
			yb = yr;
		}
		if (xa.compareTo(BigInteger.ZERO) < 0) {
			xa = xa.add(temp);
		}

		System.out.println("Private key d = " + xa);
		return xa;
	}

	// Tính y = x^a mod n
	static BigInteger powMod(BigInteger x, BigInteger a, BigInteger n) {
		String binaryA = decimalToBinary(a); // Đổi a sang binary
		BigInteger y = BigInteger.ONE;
		for (int i = 0; i < binaryA.length(); i++) {
			y = y.multiply(y);
			y = y.mod(n);
			if (binaryA.charAt(i) == '1') {
				y = y.multiply(x);
				y = y.mod(n);
			}
		}
		return y;
	}

	// Đổi word (hệ 27) sang số hệ 10
	static BigInteger wordToNumber(String word) {
		int length = word.length() - 1;
		BigInteger result = BigInteger.ZERO;
		for (int i = 0; i < word.length(); i++) {
			BigInteger temp = new BigInteger("27");
			temp = temp.pow(length); // 27 ^ length
			temp = temp.multiply(new BigInteger(Integer.toString((int) word.charAt(i) - 96)));
			result = result.add(temp);
			length--;
		}
		return result;
	}

	// Đổi số hệ 10 sang word (hệ 27)
	static String numberToWord(BigInteger number) {
		String word = new String();
		long temp;
		while (number.compareTo(BigInteger.ZERO) > 0) {
			temp = number.mod(new BigInteger("27")).intValue() + 96;
			word += (char) temp;
			number = number.divide(new BigInteger("27"));
		}
		StringBuilder result = new StringBuilder(word);
		return new String(result.reverse());
	}

	// Đổi số hệ 10 sang số nhị phân
	static String decimalToBinary(BigInteger decimal) {
		String word = new String();
		while (decimal.compareTo(BigInteger.ZERO) > 0) {
			word += String.valueOf(decimal.mod(new BigInteger("2")));
			decimal = decimal.divide(new BigInteger("2"));
		}
		StringBuilder result = new StringBuilder(word);
		return new String(result.reverse());
	}

	// Tính căn bậc hai của một số BigInteger
	static BigInteger sqrt(BigInteger n) {
		BigInteger a = BigInteger.ONE;
		BigInteger b = n.shiftRight(5).add(BigInteger.valueOf(8));
		while (b.compareTo(a) >= 0) {
			BigInteger mid = a.add(b).shiftRight(1);
			if (mid.multiply(mid).compareTo(n) > 0) {
				b = mid.subtract(BigInteger.ONE);
			} else {
				a = mid.add(BigInteger.ONE);
			}
		}
		return a.subtract(BigInteger.ONE);
	}

}