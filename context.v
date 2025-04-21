module pslhdsa

import crypto.sha256
import crypto.sha512
import crypto.sha3 // for shake
import crypto.hmac

// SLH-DSA Context
struct Context {
	// Chapter 11. Parameters Set
	kind Kind
	n    int
	h    int
	d    int
	hp   int
	a    int
	k    int
	lgw  int = 4
	m    int
	sc   int
	pkb  int
	sig  int
}

fn new_context(k Kind) Context {
	prm := paramset[k.str()]
	return Context{
		kind: k
		n:    prm.n
		h:    prm.h
		d:    prm.d
		hp:   prm.hp
		a:    prm.a
		k:    prm.k
		lgw:  prm.lgw // int = 4
		m:    prm.m
		sc:   prm.sc
		pkb:  prm.pkb
		sig:  prm.sig
	}
}

// is_shake tells underlying hash was a shake-family algorithm
@[inline]
fn (c Context) is_shake() bool {
	return c.kind.is_shake()
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
		data << to_bytes(u64(c), 4)
		// seed + to_bytes(c, 4)
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
		data << to_bytes(u64(c), 4)
		// seed + to_bytes(c, 4)
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
	data << to_bytes(0, 64 - c.n)
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
	out := if c.sc == 1 {
		// security category 1
		hmac_sha256(sk_prf, data)
	} else {
		// security category 3 and 5
		hmac_sha512(sk_prf, data)
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
	data << to_bytes(0, 64 - c.n)
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
		data << to_bytes(0, 64 - c.n)
	} else {
		data << to_bytes(0, 128 - c.n)
	}
	data << addrs_c
	data << m2

	out := if c.sc == 1 { sha256.sum256(data) } else { sha512.sum512(data) }
	return out[..c.n]
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
fn (c Context) tlen(el_len int, pk_seed []u8, addr Address, ml []u8) ![]u8 {
	assert ml.len == el_len * c.n
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
		data << to_bytes(0, 64 - c.n)
	} else {
		data << to_bytes(0, 128 - c.n)
	}
	data << addrs_c
	data << ml
	out := if c.sc == 1 {
		sha256.sum256(data)
	} else {
		// SLH-DSA Using SHA2 for Security Categories 3 and 5
		// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
		sha512.sum512(data)
	}
	return out[..c.n]
}
