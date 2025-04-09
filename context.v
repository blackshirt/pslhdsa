module pslhdsa

// 4. Functions and Addressing
// import crypto.sha256
// import crypto.sha512
// import crypto.sha3 // for shake
// import crypto.hmac

// The enumeration type of the SLH-DSA key.
// See Table 2. SLH-DSA parameter sets of the Chapter 11. Parameter Sets<br>
// Each sets name indicates:
//
// 	- the hash function family (SHA2 or SHAKE) that is used to instantiate the hash functions.
//	- the length in bits of the security parameter, in the 128, 192, and 256 respectives number.
//	- the mnemonic name indicates parameter to create relatively small signatures (`s`)
//	  or to have relatively fast signature generation (`f`).
pub enum Kind {
	// SHA2-based family
	sha2_128s
	sha2_128f
	sha2_192s
	sha2_192f
	sha2_256s
	sha2_256f
	// SHAKE-based family
	shake_128s
	shake_128f
	shake_192s
	shake_192f
	shake_256s
	shake_256f
}

@[inline]
fn (k Kind) is_shake() bool {
	match k {
		.shake_128s, .shake_128f, .shake_192s, .shake_192f, .shake_256s, .shake_256f { return true }
		else { return false }
	}
}

// nsize returns the size of underlying n parameter from current type.
@[inline]
fn (n Kind) nsize() int {
	match n {
		.sha2_128s, .sha2_128f, .shake_128s, .shake_128f { return 16 }
		.sha2_192s, .sha2_192f, .shake_192s, .shake_192f { return 24 }
		.sha2_256s, .sha2_256f, .shake_256s, .shake_256f { return 32 }
	}
}

fn (n Kind) str() string {
	match n {
		// vfmt off
		// SHA2-based family
		.sha2_128s { return "sha2_128s" }
		.sha2_128f { return "sha2_128f" }
		.sha2_192s { return "sha2_192s" }
		.sha2_192f { return "sha2_192f" }
		.sha2_256s { return "sha2_256s" }
		.sha2_256f { return "sha2_256f" }
		// SHAKE-based family
		.shake_128s { return "shake_128s" }
		.shake_128f { return "shake_128f" }
		.shake_192s { return "shake_192s" }
		.shake_192f { return "shake_192f" }
		.shake_256s { return "shake_256s" }
		.shake_256f { return "shake_256f" }
		// vfmt on
	}
}

// Chapter 11. Parameters Set
struct ParamSet {
	// Algorithm name
	id  Kind
	n   int
	h   int
	d   int
	hp  int
	a   int
	k   int
	lgw int = 4
	m   int
	sc  int
	pkb int
	sig int
}

// When 𝑙𝑔𝑤 = 4, 𝑤 = 16, 𝑙𝑒𝑛1 = 2𝑛, 𝑙𝑒𝑛2 = 3, and 𝑙𝑒𝑛 = 2𝑛 + 3.
// See FIPS 205 p17
const w = 16
const len2 = 3

@[inline]
fn (p ParamSet) len1() int {
	return 2 * p.n
}

@[inline]
fn (p ParamSet) wots_len() int {
	return 2 * p.n + 3
}

// Table 2. SLH-DSA parameter sets
const paramset = {
	// 						     id 	𝑛 	ℎ 	𝑑 	ℎ′  𝑎 	𝑘 	𝑙𝑔𝑤 𝑚  sc pkb  sig
	'sha2_128s':  ParamSet{.sha2_128s, 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'sha2_128f':  ParamSet{.sha2_128f, 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'sha2_192s':  ParamSet{.sha2_192s, 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'sha2_192f':  ParamSet{.sha2_192f, 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'sha2_256s':  ParamSet{.sha2_256s, 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'sha2_256f':  ParamSet{.sha2_256f, 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
	// SHAKE family
	'shake_128s': ParamSet{.shake_128s, 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'shake_128f': ParamSet{.shake_128f, 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'shake_192s': ParamSet{.shake_192s, 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'shake_192f': ParamSet{.shake_192f, 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'shake_256s': ParamSet{.shake_256s, 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'shake_256f': ParamSet{.shake_256f, 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
}

fn ParamSet.from_kind(k Kind) ParamSet {
	return paramset[k.str()]
}
