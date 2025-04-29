module pslhdsa

import crypto.sha256
import crypto.sha512
import crypto.sha3 // for shake
import crypto.hmac

// SLH-DSA Context
struct Context {
mut:
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
	mut ctx := Context{
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

	return ctx
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
		mut data := []u8{}
		data << seed
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
		mut data := []u8{}
		data << seed
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
// sha256_digest of the message to be signed.
fn (mut c Context) h_msg(r []u8, pk_seed []u8, pk_root []u8, m []u8) ![]u8 {
	if c.is_shake() {
		// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = SHAKE256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀, 8𝑚)
		mut data := []u8{}
		data << r
		data << pk_seed
		data << pk_root
		data << m
		return sha3.shake256(data, c.m)
	}
	// SLH-DSA Using SHA2 for Security Category 1
	//
	// mgf1_sha256(R + pk_seed + sha256(R + pk_seed + pk_root + M)
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	if c.kind == .sha2_128f || c.kind == .sha2_128s {
		mut data := []u8{}
		data << r
		data << pk_seed
		data << pk_root
		data << m

		digest := sha256.sum256(data)

		mut seed := []u8{}
		seed << r
		seed << pk_seed
		seed << digest

		return mgf1_sha256(seed, c.m)
	}
	// else .sha2_192f, .sha2_192s, .sha2_256f, .sha2_256s
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	//
	// H𝑚𝑠𝑔, PRF, PRF𝑚𝑠𝑔, F, H, and Tℓ shall be instantiated as follows forthe SLH-DSA-SHA2-192s,
	// SLH-DSA-SHA2-192f, SLH-DSA-SHA2-256s, and SLH-DSA-SHA2-256f parameter sets:
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	mut data := []u8{}
	data << r
	data << pk_seed
	data << pk_root
	data << m

	digest := sha512.sum512(data)

	mut seed := []u8{}
	seed << r
	seed << pk_seed
	seed << digest

	return mgf1_sha512(seed, c.m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
fn (mut c Context) prf(pk_seed []u8, sk_seed []u8, addr Address) ![]u8 {
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
	if c.kind == .sha2_128f || c.kind == .sha2_128s {
		mut data := []u8{}
		data << pk_seed
		data << to_bytes(0, 64 - c.n)
		data << addrs_c
		data << sk_seed

		digest := sha256.sum256(data)
		return digest[..c.n]
	}
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	//
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	// Really the same with category 1
	mut data := []u8{}
	data << pk_seed
	data << to_bytes(0, 64 - c.n)
	data << addrs_c
	data << sk_seed

	digest := sha256.sum256(data)
	return digest[..c.n]
}

// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
fn (mut c Context) prf_msg(sk_prf []u8, opt_rand []u8, msg []u8) ![]u8 {
	if c.is_shake() {
		// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)
		mut data := []u8{}
		data << sk_prf
		data << opt_rand
		data << msg

		return sha3.shake256(data, c.n)
	}
	// sha2 family
	// SLH-DSA Using SHA2 for Security Category 1
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	if c.kind == .sha2_128f || c.kind == .sha2_128s {
		mut data := []u8{}
		data << opt_rand
		data << msg

		digest := hmac_sha256(sk_prf, data)
		return digest[..c.n]
	}
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-512(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	mut data := []u8{}
	data << opt_rand
	data << msg
	digest := hmac_sha512(sk_prf, data)

	return digest[..c.n]
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
fn (mut c Context) f(pk_seed []u8, addr Address, m1 []u8) ![]u8 {
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
	addrs_c := addr.compress()
	if c.kind == .sha2_128s || c.kind == .sha2_128f {
		mut data := []u8{}
		data << pk_seed
		data << to_bytes(0, 64 - c.n)
		data << addrs_c
		data << m1

		digest := sha256.sum256(data)
		return digest[..c.n]
	}
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	//
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	mut data := []u8{}
	data << pk_seed
	data << to_bytes(0, 64 - c.n)
	data << addrs_c
	data << m1

	digest := sha256.sum256(data)
	return digest[..c.n]
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
fn (mut c Context) h(pk_seed []u8, addr Address, m2 []u8) ![]u8 {
	if c.is_shake() {
		// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.bytes()
		data << m2

		return sha3.shake256(data, c.n)
	}
	// compressed form used in sha2 hashing routines
	addrs_c := addr.compress()
	// SLH-DSA Using SHA2 for Security Category 1
	//
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	if c.kind == .sha2_128f || c.kind == .sha2_128s {
		mut data := []u8{}
		data << pk_seed
		data << to_bytes(0, 64 - c.n)
		data << addrs_c
		data << m2

		digest := sha256.sum256(data)
		return digest[..c.n]
	}
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	//
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	mut data := []u8{}
	data << pk_seed
	data << to_bytes(0, 128 - c.n)
	data << addrs_c
	data << m2

	digest := sha512.sum512(data)
	return digest[..c.n]
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
fn (mut c Context) tlen(pk_seed []u8, addr Address, ml []u8) ![]u8 {
	assert ml.len % c.n == 0
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
	if c.kind == .sha2_128f || c.kind == .sha2_128s {
		mut data := []u8{}
		data << pk_seed
		data << to_bytes(0, 64 - c.n)
		data << addrs_c
		data << ml

		digest := sha256.sum256(data)
		return digest[..c.n]
	}
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	//
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	mut data := []u8{}
	data << pk_seed
	data << to_bytes(0, 128 - c.n)
	data << addrs_c
	data << ml

	digest := sha512.sum512(data)
	return digest[..c.n]
}
