// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Parameter Set
module pslhdsa

import crypto.hmac
import crypto.sha3
import crypto.sha256
import crypto.sha512

@[noinit]
struct SlhContext {
mut:
	kind   Kind // set on creation
	psfunc PrfFuncs
	prm    Param
}

@[inline]
fn new_slhcontext(k Kind) !&SlhContext {
	return &SlhContext{
		kind:   k
		psfunc: new_psfunc(k)
		prm:    new_param(k)
	}
}

@[inline]
fn new_psfunc(k Kind) PrfFuncs {
	match k {
		.shake_128f, .shake_128s, .shake_192f, .shake_192s, .shake_256f, .shake_256s {
			return new_shakeprf()
		}
		// for the SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f parameter sets Using SHA2 for Security Category 1
		.sha2_128f, .sha2_128s {
			return new_sha2prf_cat1()
		}
		// for sha2_192s and sha2_192f has Security Category 3
		.sha2_192f, .sha2_192s {
			return new_sha2prf_cat3()
		}
		// otherwise is Security Category 5
		.sha2_256f, .sha2_256s {
			return new_sha2prf_cat5()
		}
	}
}

// SLH-DSA Parameter set
//
@[noinit]
struct Param {
mut:
	// The id (name) indicates SLH-DSA its belong to
	id string
	// the length in bits of the security parameter 𝑛, Its parameters for WOTS+
	n int
	// XMSS and the SLH-DSA hypertree (ℎ and 𝑑)
	h int
	d int
	//  A Merkle tree of height ℎ′
	hp int

	// FORS parameters (𝑘 and 𝑎)
	a int
	k int
	// The parameter 𝑙𝑔𝑤 indicates the number of bits that are encoded by each
	// hash chain that is used. 𝑙𝑔𝑤 is 4 for all parameter sets in this standard
	// Its parameters for WOTS+
	lgw int = 4
	// SLH-DSA uses one additional parameter 𝑚, which is the length in bytes of the message digest.
	m int
	// security category
	sc int
	// public key size
	pklen int
	// signature size
	siglen int
}

// new_param creates SLH-DSA parameter set from Kind k
@[inline]
fn new_param(k Kind) Param {
	return paramset[k.str()]
}

// Table 2. SLH-DSA parameter sets
const paramset = {
	// 						     		id   𝑛   ℎ   𝑑  ℎp  𝑎  𝑘  𝑙𝑔𝑤 𝑚  sc pklen siglen
	'sha2_128s':  Param{'SLH-DSA-SHA2-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'sha2_128f':  Param{'SLH-DSA-SHA2-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'sha2_192s':  Param{'SLH-DSA-SHA2-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'sha2_192f':  Param{'SLH-DSA-SHA2-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'sha2_256s':  Param{'SLH-DSA-SHA2-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'sha2_256f':  Param{'SLH-DSA-SHA2-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
	// SHAKE family
	'shake_128s': Param{'SLH-DSA-SHAKE-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'shake_128f': Param{'SLH-DSA-SHAKE-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'shake_192s': Param{'SLH-DSA-SHAKE-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'shake_192f': Param{'SLH-DSA-SHAKE-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'shake_256s': Param{'SLH-DSA-SHAKE-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'shake_256f': Param{'SLH-DSA-SHAKE-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
}

// Hash Functions and Pseudorandom Functions
//
// PrfFuncs is a hashing and or pseudorandom functions used in the mean time of SLH-DSA operation.
interface PrfFuncs {
	// pseudorandom function (PRF) that generates the randomizer (𝑅)
	// for the randomized hashing of the message to be signed
	prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8
	// hmsg was used to generate the digest of the message to be signed.
	hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8
	// prf is a pseudorandom function  (PRF) that is used to generate the secret values
	// in WOTS+ and FORS private keys.
	prf(pkseed []u8, skseed []u8, adr Address, outlen int) ![]u8
	// tl is a hash function that maps an ℓ𝑛-byte message to an 𝑛-byte message.
	tl(pkseed []u8, adr Address, ml [][]u8, outlen int) ![]u8
	// h is a special case of Tℓ that takes a 2𝑛-byte message as input.
	h(pkseed []u8, adr Address, m2 []u8, outlen int) ![]u8
	// f is a hash function that takes an 𝑛-byte message as input and produces an 𝑛-byte output.
	f(pkseed []u8, adr Address, m1 []u8, outlen int) ![]u8
}

// SHAKE based SLH-DSA pseudorandom function
//
// See 11.1 SLH-DSA Using SHAKE
struct ShakePrf {}

fn new_shakeprf() &ShakePrf {
	return &ShakePrf{}
}

@[direct_array_access]
fn (s &ShakePrf) prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8 {
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)
	mut data := []u8{cap: skprf.len + optrand.len + msg.len}

	data << skprf
	data << optrand
	data << msg

	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s &ShakePrf) hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8 {
	size := r.len + pkseed.len + pkroot.len + msg.len
	mut data := []u8{cap: size}
	data << r
	data << pkseed
	data << pkroot
	data << msg
	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s &ShakePrf) prf(pkseed []u8, skseed []u8, adr Address, outlen int) ![]u8 {
	// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)
	// adr.bytes() == 32
	size := pkseed.len + skseed.len + 32 + skseed.len
	mut data := []u8{cap: size}
	data << pkseed
	data << adr.bytes()
	data << skseed
	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s &ShakePrf) tl(pkseed []u8, adr Address, m1 [][]u8, outlen int) ![]u8 {
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)
	mut m1size := 0
	for o in m1 {
		m1size += o.len
	}
	size := pkseed.len + 32 + m1size
	mut data := []u8{cap: size}
	data << pkseed
	data << adr.bytes()
	for item in m1 {
		data << item
	}

	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s &ShakePrf) h(pkseed []u8, adr Address, m2 []u8, outlen int) ![]u8 {
	// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
	mut data := []u8{cap: pkseed.len + 32 + m2.len}
	data << pkseed
	data << adr.bytes()
	data << m2

	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s &ShakePrf) f(pkseed []u8, adr Address, m1 []u8, outlen int) ![]u8 {
	// F(PK.seed, ADRS, 𝑀1) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)
	mut data := []u8{cap: pkseed.len + 32 + m1.len}
	data << pkseed
	data << adr.bytes()
	data << m1

	return sha3.shake256(data, outlen)
}

// 11.2.1 SLH-DSA Using SHA2 for Security Category 1
//
struct Sha2PRFCategory1 {}

fn new_sha2prf_cat1() &Sha2PRFCategory1 {
	return &Sha2PRFCategory1{}
}

// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
fn (s &Sha2PRFCategory1) prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8 {
	mut data := []u8{cap: optrand.len + msg.len}
	data << optrand
	data << msg

	digest := hmac_sha256(skprf, data)
	return digest[..outlen].clone()
}

fn (s &Sha2PRFCategory1) hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8 {
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	mut h := sha256.new()
	mut seed := []u8{cap: r.len + pkseed.len}
	seed << r
	seed << pkseed

	mut inner := sha256.new()
	inner.write(r)!
	inner.write(pkseed)!
	inner.write(pkroot)!
	inner.write(msg)!

	innerhash := inner.sum([]u8{})

	mut newseed := []u8{cap: seed.len + innerhash.len}
	newseed << seed
	newseed << innerhash

	// mgf1(seed []u8, masklen int, mut h hash.Hash) ![]u8
	return mgf1(newseed, outlen, mut h)!
}

// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
fn (s &Sha2PRFCategory1) prf(pkseed []u8, skseed []u8, adr Address, outlen int) ![]u8 {
	cadr := adr.compress()
	// For category 1, n == 16, and 64-16 = 48
	size := pkseed.len + 48 + 22 + skseed.len
	mut data := []u8{cap: size}
	data << pkseed
	data << to_byte(0, 64 - 16)
	data << cadr
	data << skseed

	digest := sha256.sum256(data)
	return digest[..outlen].clone()
}

fn (s &Sha2PRFCategory1) tl(pkseed []u8, adr Address, ml [][]u8, outlen int) ![]u8 {
	// SLH-DSA Using SHA2 for Security Category 1
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	cadrs := adr.compress()

	mut h := sha256.new()
	h.write(pkseed)!
	h.write(to_byte(0, 48))!
	h.write(cadrs)!
	for item in ml {
		h.write(item)!
	}
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

fn (s &Sha2PRFCategory1) h(pkseed []u8, adr Address, m2 []u8, outlen int) ![]u8 {
	// SLH-DSA Using SHA2 for Security Category 1
	//
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	adrsc := adr.compress()
	// get the size and n == 16
	size := pkseed.len + 48 + 22 + m2.len
	mut data := []u8{cap: size}

	data << pkseed
	data << to_byte(0, 64 - 16)
	data << adrsc
	data << m2

	digest := sha256.sum256(data)
	return digest[..outlen].clone()
}

fn (s &Sha2PRFCategory1) f(pkseed []u8, adr Address, m1 []u8, outlen int) ![]u8 {
	// 11.2.1 SLH-DSA Using SHA2 for Security Category 1
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	adrsc := adr.compress()
	// get the size and n == 16
	size := pkseed.len + 48 + 22 + m1.len
	mut data := []u8{cap: size}

	// concatenates the message
	data << pkseed
	data << to_byte(0, 64 - 16)
	data << adrsc
	data << m1

	digest := sha256.sum256(data)
	return digest[..outlen].clone()
}

// 11.2.2 SLH-DSA Using SHA2 for Security Categories 3
//
// n == 24
struct Sha2PRFCategory3 {}

fn new_sha2prf_cat3() &Sha2PRFCategory3 {
	return &Sha2PRFCategory3{}
}

@[direct_array_access]
fn (s &Sha2PRFCategory3) prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8 {
	// SLH-DSA Using SHA2 for Security Categories 3
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-512(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	mut data := []u8{cap: optrand.len + msg.len}
	data << optrand
	data << msg

	digest := hmac_sha512(skprf, data)
	return digest[0..outlen].clone()
}

@[direct_array_access]
fn (s &Sha2PRFCategory3) hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8 {
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	mut h := sha512.new()
	mut seed := []u8{cap: r.len + pkseed.len}
	seed << r
	seed << pkseed

	mut inner := sha512.new()

	inner.write(r)!
	inner.write(pkseed)!
	inner.write(pkroot)!
	inner.write(msg)!
	innerhash := inner.sum([]u8{})
	seed << innerhash

	return mgf1(seed, outlen, mut h)
}

@[direct_array_access]
fn (s &Sha2PRFCategory3) prf(pkseed []u8, skseed []u8, adr Address, outlen int) ![]u8 {
	cadrs := adr.compress()
	// security category 3, n == 24,
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	mut h := sha256.new()
	h.write(pkseed)!
	h.write(to_byte(0, 64 - 24))!
	h.write(cadrs)!
	h.write(skseed)!
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

@[direct_array_access]
fn (s &Sha2PRFCategory3) tl(pkseed []u8, adr Address, ml [][]u8, outlen int) ![]u8 {
	cadrs := adr.compress()
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	mut h := sha512.new()
	h.write(pkseed)!
	h.write(to_byte(0, 128 - 24))!
	h.write(cadrs)!
	for val in ml {
		h.write(val)!
	}
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

@[direct_array_access]
fn (s &Sha2PRFCategory3) h(pkseed []u8, adr Address, m2 []u8, outlen int) ![]u8 {
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	return sha512_generic(24, pkseed, adr, m2, outlen)
}

@[direct_array_access]
fn (s &Sha2PRFCategory3) f(pkseed []u8, adr Address, m1 []u8, outlen int) ![]u8 {
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	return sha256_generic(24, pkseed, adr, m1, outlen)
}

// // 11.2.2 SLH-DSA Using SHA2 for Security Categories 5
struct Sha2PRFCategory5 {}

@[inline]
fn new_sha2prf_cat5() &Sha2PRFCategory5 {
	return &Sha2PRFCategory5{}
}

fn (s &Sha2PRFCategory5) prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8 {
	// SLH-DSA Using SHA2 for Security Categories 5
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-512(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	mut data := []u8{}
	data << optrand
	data << msg
	digest := hmac_sha512(skprf, data)

	return digest[0..outlen].clone()
}

fn (s &Sha2PRFCategory5) hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8 {
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	mut h := sha512.new()
	mut seed := []u8{cap: 2 * r.len + 2 * pkseed.len + pkroot.len + msg.len}
	seed << r
	seed << pkseed

	mut inner := sha512.new()
	inner.write(r)!
	inner.write(pkseed)!
	inner.write(pkroot)!
	inner.write(msg)!
	innerhash := inner.sum([]u8{})
	seed << innerhash

	return mgf1(seed, outlen, mut h)
}

fn (s &Sha2PRFCategory5) prf(pkseed []u8, skseed []u8, adr Address, outlen int) ![]u8 {
	cadrs := adr.compress()
	// n == 32
	mut h := sha256.new()
	h.write(pkseed)!
	h.write(to_byte(0, 64 - 32))!
	h.write(cadrs)!
	h.write(skseed)!
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

fn (s &Sha2PRFCategory5) tl(pkseed []u8, adr Address, ml [][]u8, outlen int) ![]u8 {
	cadrs := adr.compress()
	mut h := sha512.new()
	h.write(pkseed)!
	h.write(to_byte(0, 128 - 32))!
	h.write(cadrs)!
	for val in ml {
		h.write(val)!
	}
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

fn (s &Sha2PRFCategory5) h(pkseed []u8, adr Address, m2 []u8, outlen int) ![]u8 {
	return sha512_generic(32, pkseed, adr, m2, outlen)
}

fn (s &Sha2PRFCategory5) f(pkseed []u8, adr Address, m1 []u8, outlen int) ![]u8 {
	return sha256_generic(32, pkseed, adr, m1, outlen)
}

// Helpers for pseudorandom function
//
@[direct_array_access; inline]
fn sha256_generic(n int, pkseed []u8, adr Address, msg []u8, outlen int) ![]u8 {
	// SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	cadr := adr.compress()

	mut h := sha256.new()

	h.write(pkseed)!
	h.write(to_byte(0, 64 - n))!
	h.write(cadr)!
	h.write(msg)!
	out := h.sum([]u8{})

	return out[0..outlen].clone()
}

@[direct_array_access; inline]
fn sha512_generic(n int, pkseed []u8, adr Address, msg []u8, outlen int) ![]u8 {
	cadr := adr.compress()
	mut h := sha512.new()
	h.write(pkseed)!
	h.write(to_byte(0, 128 - n))!
	h.write(cadr)!
	h.write(msg)!
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

@[inline]
fn hmac_sha256(seed []u8, data []u8) []u8 {
	// fn new(key []u8, data []u8, hash_func fn ([]u8) []u8, blocksize int) []u8
	return hmac.new(seed, data, sha256.sum256, sha256.block_size)
}

@[inline]
fn hmac_sha512(seed []u8, data []u8) []u8 {
	// fn new(key []u8, data []u8, hash_func fn ([]u8) []u8, blocksize int) []u8
	return hmac.new(seed, data, sha512.sum512, sha512.block_size)
}

// The enumeration type of the SLH-DSA key.
// See Table 2. SLH-DSA parameter sets of the Chapter 11. Parameter Sets<br>
//
// Each sets name indicates:
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

@[inline]
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
		else { return error('Invalid SLH-DSA name string') }
	}
}

@[inline]
fn (n Kind) long_name() string {
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
		// SHA2-based family
		.sha2_128s { return 'sha2_128s' }
		.sha2_128f { return 'sha2_128f' }
		.sha2_192s { return 'sha2_192s' }
		.sha2_192f { return 'sha2_192f' }
		.sha2_256s { return 'sha2_256s' }
		.sha2_256f { return 'sha2_256f' }
		// SHAKE-based family
		.shake_128s { return 'shake_128s' }
		.shake_128f { return 'shake_128f' }
		.shake_192s { return 'shake_192s' }
		.shake_192f { return 'shake_192f' }
		.shake_256s { return 'shake_256s' }
		.shake_256f { return 'shake_256f' }
	}
}
