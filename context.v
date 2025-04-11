module pslhdsa

import crypto.sha256
import crypto.sha512
import crypto.sha3 // for shake
import crypto.hmac

// SLH-DSA Context
struct Context {
	// Chapter 11. Parameters Set
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

fn new_context(k Kind) Context {
	return paramset[k.str()]
}

// is_shake tells underlying hash was a shake-family algorithm
@[inline]
fn (c Context) is_shake() bool {
	return c.id.is_shake()
}

// When 𝑙𝑔𝑤 = 4, 𝑤 = 16, 𝑙𝑒𝑛1 = 2𝑛, 𝑙𝑒𝑛2 = 3, and 𝑙𝑒𝑛 = 2𝑛 + 3.
// See FIPS 205 p17
const w = 16
const len2 = 3

@[inline]
fn (c Context) len1() int {
	return 2 * c.n
}

@[inline]
fn (c Context) wots_len() int {
	return 2 * c.n + 3
}

const sha256_hash_size = sha256.size

// A mask generation function (MGF) is a cryptographic primitive similar
// to a cryptographic hash function except that while a hash function's
// output has a fixed size, a MGF supports output of a variable length.
@[inline]
fn mgf1_sha256(seed []u8, mlen int) []u8 {
	mut out := []u8{}
	for c := 0; c < cdiv(mlen, sha256_hash_size); c++ {
		mut data := seed.clone()
		data << to_byte(u64(c), 4)
		// seed + to_byte(c, 4)
		out << sha256.sum256(data)
	}
	return out[..mlen]
}

const sha512_hash_size = sha512.size

@[inline]
fn mgf1_sha512(seed []u8, mlen int) []u8 {
	mut out := []u8{}
	for c := 0; c < cdiv(mlen, sha512_hash_size); c++ {
		mut data := seed.clone()
		data << to_byte(u64(c), 4)
		// seed + to_byte(c, 4)
		out << sha512.sum512(data)
	}
	return out[..mlen]
}

@[inline]
fn hmac_sha256(seed []u8, data []u8) []u8 {
	out := hmac.new(seed, data, sha256.sum256, sha256.size)
	return out
}

@[inline]
fn hmac_sha512(seed []u8, data []u8) []u8 {
	return hmac.new(seed, data, sha512.sum512, sha512.size)
}

// 4.1 Hash Functions and Pseudorandom Functions
//
// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚) is used to generate the
// digest of the message to be signed.
fn (c Context) h_msg(r []u8, pk_seed []u8, pk_root []u8, m []u8) ![]u8 {
	if c.is_shake() {
		// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = SHAKE256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀, 8𝑚)
		mut data := []u8{}
		data << r
		data << pk_seed
		data << pk_root
		data << m
		return sha3.shake256(data, c.m)
	}
	// mgf1_sha256(R + pk_seed + sha256(R + pk_seed + pk_root + M)
	mut first_seed := []u8{}
	first_seed << r
	first_seed << pk_seed

	mut second_seed := first_seed.clone()
	second_seed << pk_root
	second_seed << m

	mut hashed_2nd_seed := sha256.sum256(second_seed)

	if c.sc != 1 {
		hashed_2nd_seed = sha512.sum512(second_seed)
	}

	mut seed := []u8{}
	seed << first_seed
	seed << hashed_2nd_seed

	if c.sc != 1 {
		return mgf1_sha512(seed, c.m)
	}
	return mgf1_sha256(seed, c.m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
fn (c Context) prf(pk_seed []u8, sk_seed []u8, addr Address) ![]u8 {
	if c.is_shake() {
		// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.bytes()
		data << sk_seed
		return sha3.shake256(data, c.n)
	}
	// sha2 family,
	// SLH-DSA Using SHA2 for Security Category 1
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << to_byte(0, 64 - c.n)
	data << addrs_c
	data << sk_seed
	mut out := sha256.sum256(data)
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	// Really the same with category 1
	// if c.sc != 1 {
	//	out = sha512.sum512(data)
	// }
	return out[..c.n]
}

// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
fn (c Context) prf_msg(sk_prf []u8, opt_rand []u8, msg []u8) ![]u8 {
	if c.is_shake() {
		// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)
		mut data := []u8{}
		data << sk_prf
		data << opt_rand
		data << msg

		return sha3.shake256(data, c.n)
	}
	// sha2 family
	mut data := []u8{}
	data << msg
	data << opt_rand
	mut out := hmac_sha256(sk_prf, data)

	if c.sc != 1 {
		out = hmac_sha512(sk_prf, data)
	}
	return out[..c.n]
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
fn (c Context) f(pk_seed []u8, addr Address, m1 []u8) ![]u8 {
	if c.is_shake() {
		// F(PK.seed, ADRS, 𝑀1) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.bytes()
		data << m1

		return sha3.shake256(data, c.n)
	}
	// 11.2.1 SLH-DSA Using SHA2 for Security Category 1
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << to_byte(0, 64 - c.n)
	data << addrs_c
	data << m1

	out := sha256.sum256(data)
	return out[..c.n]
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
fn (c Context) h(pk_seed []u8, addr Address, m2 []u8) ![]u8 {
	if c.is_shake() {
		// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.bytes()
		data << m2

		return sha3.shake256(data, c.n)
	}
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed

	if c.sc == 1 {
		data << to_byte(0, 64 - c.n)
	} else {
		data << to_byte(0, 128 - c.n)
	}
	data << addrs_c
	data << m2

	mut out := sha256.sum256(data)
	if c.sc != 1 {
		out = sha512.sum512(data)
	}
	return out[..c.n]
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
fn (c Context) tlen(pk_seed []u8, addr Address, ml []u8) ![]u8 {
	if c.is_shake() {
		// Tℓ(PK.seed, ADRS, 𝑀ℓ) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.bytes()
		data << ml

		return sha3.shake256(data, c.n)
	}
	// sha2 family,
	//
	// SLH-DSA Using SHA2 for Security Category 1
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed
	if c.sc == 1 {
		data << to_byte(0, 64 - c.n)
	} else {
		data << to_byte(0, 128 - c.n)
	}
	data << addrs_c
	data << ml
	mut out := sha256.sum256(data)
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	if c.sc != 1 {
		out = sha512.sum512(data)
	}
	return out[..c.n]
}

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

fn kind_from_longname(s string) !Kind {
	match s {
		// SHA2-based family
		'SLH-DSA-SHA2-128s' { return .sha2_128s }
		'SLH-DSA-SHA2-128f' { return .sha2_128f }
		'SLH-DSA-SHA2-192s' { return .sha2_192s }
		'SLH-DSA-SHA2-192f' { return .sha2_192f }
		'SLH-DSA-SHA2-256s' { return .sha2_256s }
		'SLH-DSA-SHA2-256f' { return .sha2_256f }
		// SHAKE-based family
		'SLH-DSA-SHAKE-128s' { return .shake_128s }
		'SLH-DSA-SHAKE-128f' { return .shake_128f }
		'SLH-DSA-SHAKE-192s' { return .shake_192s }
		'SLH-DSA-SHAKE-192f' { return .shake_192f }
		'SLH-DSA-SHAKE-256s' { return .shake_256s }
		'SLH-DSA-SHAKE-256f' { return .shake_256f }
		else { return error('Unsupported long name string') }
	}
}

fn (n Kind) long_name() !string {
	match n {
		// SHA2-based family
		.sha2_128s { return 'SLH-DSA-SHA2-128s' }
		.sha2_128f { return 'SLH-DSA-SHA2-128f' }
		.sha2_192s { return 'SLH-DSA-SHA2-192s' }
		.sha2_192f { return 'SLH-DSA-SHA2-192f' }
		.sha2_256s { return 'SLH-DSA-SHA2-256s' }
		.sha2_256f { return 'SLH-DSA-SHA2-256f' }
		// SHAKE-based family
		.shake_128s { return 'SLH-DSA-SHAKE-128s' }
		.shake_128f { return 'SLH-DSA-SHAKE-128f' }
		.shake_192s { return 'SLH-DSA-SHAKE-192s' }
		.shake_192f { return 'SLH-DSA-SHAKE-192f' }
		.shake_256s { return 'SLH-DSA-SHAKE-256s' }
		.shake_256f { return 'SLH-DSA-SHAKE-256f' }
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

// Table 2. SLH-DSA parameter sets
const paramset = {
	// 						     id   𝑛   ℎ   𝑑  ℎp  𝑎 	𝑘 	𝑙𝑔𝑤 𝑚 sc pkb  sig
	'sha2_128s':  Context{.sha2_128s, 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'sha2_128f':  Context{.sha2_128f, 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'sha2_192s':  Context{.sha2_192s, 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'sha2_192f':  Context{.sha2_192f, 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'sha2_256s':  Context{.sha2_256s, 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'sha2_256f':  Context{.sha2_256f, 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
	// SHAKE family
	'shake_128s': Context{.shake_128s, 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'shake_128f': Context{.shake_128f, 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'shake_192s': Context{.shake_192s, 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'shake_192f': Context{.shake_192f, 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'shake_256s': Context{.shake_256s, 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'shake_256f': Context{.shake_256f, 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
}
