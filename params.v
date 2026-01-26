// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Parameter Set and context opaque to work on SLH-DSA parameter set
module pslhdsa

import hash
import arrays
import crypto.hmac
import crypto.sha3
import crypto.sha256
import crypto.sha512

// SLH-DSA Context
//
@[noinit]
struct Context {
mut:
	// The kind (type) of this SLH-DSA context, set on context creation
	kind Kind
	// Underlying SLH-DSA parameter set described in the doc
	prm Param
}

// new_context creates a new SLH-DSA Context to operate on
@[inline]
fn new_context(k Kind) &Context {
	return &Context{
		kind: k
		prm:  new_param(k)
	}
}

// equal returns true if this context is equal to the other context
@[inline]
fn (c &Context) equal(o &Context) bool {
	// for sake of simplicity, only check for kind equality, not the parameter set
	return c.kind == o.kind
}

// Hash Addressing and Pseudorandom Functions for SLH-DSA context
//

// prf_msg is a pseudorandom function (PRF) that generates the randomizer (𝑅)
// for the randomized hashing of the message to be signed
@[direct_array_access]
fn (c &Context) prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8 {
	// setup buffer with enough capacity to avoid reallocation
	mut data := []u8{cap: skprf.len + optrand.len + msg.len}

	// Is this context was a SHAKE-based type? If yes procees with SHAKE-based PRF
	// For SHAKE-based family, use SHAKE256 hash
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)
	if c.is_shake_family() {
		data << skprf
		data << optrand
		data << msg
		// return the shake256 digest
		return sha3.shake256(data, outlen)
	}
	// Otherwise, process with SHA2-based type
	//
	// begin by appending into data buffer
	data << optrand
	data << msg

	// For SHA2-based type with security category 1, use HMAC-SHA-256 PRF
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	if c.is_sha2family_cat1() {
		digest := hmac_sha256(skprf, data)
		return digest[..outlen].clone()
	}
	// Otherwise, its should belong to type with security categories 3 or 5 and use HMAC-SHA-512 PRF
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-512(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	digest := hmac_sha512(skprf, data)

	// return the clone with appropriate outlen size
	return digest[0..outlen].clone()
}

// hmsg was used to generate the digest of the message to be signed.
@[direct_array_access]
fn (c &Context) hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8 {
	// setup buffer size to avoid reallocation by initializing enough capacity
	mut basic_size := r.len + pkseed.len + pkroot.len + msg.len
	size := if c.is_shake_family() { basic_size } else { basic_size + r.len + pkseed.len }
	mut data := []u8{cap: size}

	// Is this context was SHAKE-based family?
	//
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = SHAKE256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀, 8𝑚)
	if c.is_shake_family() {
		data << r
		data << pkseed
		data << pkroot
		data << msg
		return sha3.shake256(data, outlen)
	}
	// Otherwise, its a SHA2-based PRF
	//
	// For security category 1, use MGF1-SHA-256
	// 		H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	// For security category 3 and 5, use MGF1-SHA-512
	// 		H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)

	// 𝑅 ∥ PK.seed
	mut twos := []u8{cap: r.len + pkseed.len}
	twos << r
	twos << pkseed

	// Gets SHA2-based PRF
	mut h := c.sha2_prf()!
	mut inner := c.sha2_prf()!

	// write the data into hash, SHA-256(or 512) (𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 )
	inner.write(r)!
	inner.write(pkseed)!
	inner.write(pkroot)!
	inner.write(msg)!

	// The (𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ) digest
	innerhash := inner.sum([]u8{})

	// data acts as a new seed
	data << twos
	data << innerhash

	// mgf1(seed []u8, masklen int, mut h hash.Hash) ![]u8
	return mgf1(data, outlen, mut h)!
}

// prf is a pseudorandom function  (PRF) that is used to generate the secret values
// in WOTS+ and FORS private keys.
@[direct_array_access]
fn (c &Context) prf(pkseed []u8, skseed []u8, addr Address, outlen int) ![]u8 {
	// SHAKE-based PRF
	//
	// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)
	// addr.bytes() == 32
	if c.is_shake_family() {
		size := pkseed.len + skseed.len + 32
		mut data := []u8{cap: size}
		data << pkseed
		data << addr.bytes()
		data << skseed
		return sha3.shake256(data, outlen)
	}
	// Otherwise, its a SHA2-based PRF
	//
	// For SHA2-based PRF using SHA-256, only differs on n number, depends on the security category
	// of underlying kind of SLH-DSA parameter set
	// ie, n = 16, n = 24 and n = 32 for security category 1, 3 and 5 respectively
	//
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	//
	// start by compressing the address
	cadrs := addr.compress()

	// setup SHA256 hash
	mut h := sha256.new()
	// write PK.seed into hash
	h.write(pkseed)!

	// write toByte(0, 64 − 𝑛) into hash
	// TODO: use context prm.n number directly
	h.write(to_byte(0, 64 - c.prm.n))!
	// write compressed address and SK.seed
	h.write(cadrs)!
	h.write(skseed)!

	// generates the digest, and return it
	digest := h.sum([]u8{})

	// Only returns the clone of appropriate outlen size
	return digest[0..outlen].clone()
}

// tl is a hash function that maps an ℓ𝑛-byte message to an 𝑛-byte message.
@[direct_array_access]
fn (c &Context) tl(pkseed []u8, addr Address, msgsln [][]u8, outlen int) ![]u8 {
	// SHAKE-based PRF
	//
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)
	if c.is_shake_family() {
		mut mlsize := 0
		for obj in msgsln {
			mlsize += obj.len
		}
		size := pkseed.len + 32 + mlsize
		mut data := []u8{cap: size}
		data << pkseed
		data << addr.bytes()
		// flatten the msg
		data << arrays.flatten[u8](msgsln)

		return sha3.shake256(data, outlen)
	}
	// Otherwise its a SHA2-based PRF
	//
	// For SHA2 family with security category 1, its using SHA-256 hash
	// 		Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	// where security category 3 and 5 using SHA-512
	// 		Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))

	// setup underlying hash
	mut h := c.sha2_prf()!

	// Start by compressing the address
	cadrs := addr.compress()
	// write PK.seed
	h.write(pkseed)!

	// write toByte content based on the hash
	// NOTE: we using c.prm.n directly
	//
	// setup base number for toByte calculation
	bnum := if c.is_sha2family_cat1() { 64 } else { 128 }
	h.write(to_byte(0, bnum - c.prm.n))!

	// write compressed address, ADRS𝑐
	h.write(cadrs)!
	// write every message in the msgsln array into hash
	for item in msgsln {
		h.write(item)!
	}
	// generate the digest
	digest := h.sum([]u8{})

	// return with appropriate outlen size
	return digest[0..outlen].clone()
}

// h is a special case of Tℓ that takes a 2𝑛-byte message as input.
@[direct_array_access]
fn (c &Context) h(pkseed []u8, addr Address, m2 []u8, outlen int) ![]u8 {
	// SHAKE-based PRF
	//
	// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
	if c.is_shake_family() {
		mut data := []u8{cap: pkseed.len + 32 + m2.len}
		data << pkseed
		data << addr.bytes()
		data << m2

		return sha3.shake256(data, outlen)
	}
	// Otherwise, its a SHA2-based PRF
	//
	// For Security category 1 use SHA-256 PRF
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	if c.is_sha2family_cat1() {
		return sha256_caddr_generic(c.prm.n, pkseed, addr, m2, outlen)
	}
	// Other else should have a security category 3 or 5 using SHA-512 PRF
	//
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	return sha512_caddr_generic(c.prm.n, pkseed, addr, m2, outlen)
}

// f is a hash function that takes an 𝑛-byte message as input and produces an 𝑛-byte output.
@[direct_array_access]
fn (c &Context) f(pkseed []u8, addr Address, m1 []u8, outlen int) ![]u8 {
	// SHAKE-based PRF
	//
	// F(PK.seed, ADRS, 𝑀1) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)
	if c.is_shake_family() {
		mut data := []u8{cap: pkseed.len + 32 + m1.len}
		data << pkseed
		data << addr.bytes()
		data << m1

		return sha3.shake256(data, outlen)
	}
	// Otherwise, use SHA2-based PRF
	//
	// 11.2.1 SLH-DSA Using SHA2 for Security Category 1, (also applied to 3 and 5)
	//
	// 1 : 		F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// 3 and 5: F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// NOTE: use context prm.n number directly
	//
	return sha256_caddr_generic(c.prm.n, pkseed, addr, m1, outlen)
}

// Helpers for pseudorandom function
//
@[direct_array_access; inline]
fn sha256_caddr_generic(n int, pkseed []u8, addr Address, msg []u8, outlen int) ![]u8 {
	cadr := addr.compress()
	mut h := sha256.new()
	h.write(pkseed)!
	h.write(to_byte(0, 64 - n))!
	h.write(cadr)!
	h.write(msg)!
	out := h.sum([]u8{})

	return out[0..outlen].clone()
}

@[direct_array_access; inline]
fn sha512_caddr_generic(n int, pkseed []u8, addr Address, msg []u8, outlen int) ![]u8 {
	cadr := addr.compress()
	mut h := sha512.new()
	h.write(pkseed)!
	h.write(to_byte(0, 128 - n))!
	h.write(cadr)!
	h.write(msg)!
	out := h.sum([]u8{})
	return out[0..outlen].clone()
}

// hmac_sha256 creates HMAC bytes with SHA256 hash
@[direct_array_access; inline]
fn hmac_sha256(seed []u8, data []u8) []u8 {
	// fn new(key []u8, data []u8, hash_func fn ([]u8) []u8, blocksize int) []u8
	return hmac.new(seed, data, sha256.sum256, sha256.size)
}

// hmac_sha512 creates new HMAC bytes with SHA512 hash
@[directly; inline]
fn hmac_sha512(seed []u8, data []u8) []u8 {
	// fn new(key []u8, data []u8, hash_func fn ([]u8) []u8, blocksize int) []u8
	return hmac.new(seed, data, sha512.sum512, sha512.size)
}

// for other need, SHA2-based Security category 1 was return SHA256
// and return SHA512 otherwise
@[inline]
fn (c &Context) sha2_prf() !hash.Hash {
	if c.is_shake_family() {
		return error('not sha2-based entity')
	}
	if c.is_sha2family_cat1() {
		return sha256.new()
	}
	return sha512.new()
}

// is_shake_family tells if this context was a SHAKE-based family
@[inline]
fn (c &Context) is_shake_family() bool {
	match c.kind {
		.shake_128f, .shake_128s, .shake_192f, .shake_192s, .shake_256f, .shake_256s {
			return true
		}
		else {
			return false
		}
	}
}

// is_sha2family_cat1 tells if this context was a SHA2-based family with security category 1
@[inline]
fn (c &Context) is_sha2family_cat1() bool {
	match c.kind {
		.sha2_128f, .sha2_128s { return true }
		else { return false }
	}
}

// is_sha2family_cat1 tells if this context was a SHA2-based family with security category 3
@[inline]
fn (c &Context) is_sha2family_cat3() bool {
	match c.kind {
		.sha2_192f, .sha2_192s { return true }
		else { return false }
	}
}

// is_sha2family_cat5 tells if this context was a SHA2-based family with security category 5
@[inline]
fn (c &Context) is_sha2family_cat5() bool {
	match c.kind {
		.sha2_256f, .sha2_256s { return true }
		else { return false }
	}
}

// Param describes SLH-DSA Parameter set
//
@[noinit]
struct Param {
mut:
	// The name indicates SLH-DSA its belong to
	name string
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
	pksize int
	// signature size
	sigsize int
}

// new_param creates SLH-DSA parameter set from Kind k
@[inline]
fn new_param(k Kind) Param {
	return paramset[k.str()]
}

// Table 2. SLH-DSA parameter sets
//
// name					𝑛 	ℎ  𝑑 ℎ′ 𝑎 𝑘 𝑙𝑔𝑤 𝑚 securitycategory pkbytes sigbytes
// SLH-DSA-SHA2-128s	16 63 7 9 12 14 4 30 1 32 7 856
// SLH-DSA-SHAKE-128s 	16 63 7 9 12 14 4 30 1 32 7 856
// ----------------------------------------------------
// SLH-DSA-SHA2-128f	16 66 22 3 6 33 4 34 1 32 17 088
// SLH-DSA-SHAKE-128f 	16 66 22 3 6 33 4 34 1 32 17 088
// ----------------------------------------------------
// SLH-DSA-SHA2-192s	24 63 7 9 14 17 4 39 3 48 16 224
// SLH-DSA-SHAKE-192s 	24 63 7 9 14 17 4 39 3 48 16 224
// ----------------------------------------------------
// SLH-DSA-SHA2-192f	24 66 22 3 8 33 4 42 3 48 35 664
// SLH-DSA-SHAKE-192f 	24 66 22 3 8 33 4 42 3 48 35 664
// ----------------------------------------------------
// SLH-DSA-SHA2-256s	32 64 8 8 14 22 4 47 5 64 29 792
// SLH-DSA-SHAKE-256s 	32 64 8 8 14 22 4 47 5 64 29 792
// ----------------------------------------------------
// SLH-DSA-SHA2-256f	32 68 17 4 9 35 4 49 5 64 49 856
// SLH-DSA-SHAKE-256f 	32 68 17 4 9 35 4 49 5 64 49 856
const paramset = {
	// SHA2-based family			name     𝑛   ℎ   𝑑  ℎp  𝑎  𝑘  𝑙𝑔𝑤 𝑚  sc pksize sigsize
	'sha2_128s':  Param{'SLH-DSA-SHA2-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'sha2_128f':  Param{'SLH-DSA-SHA2-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'sha2_192s':  Param{'SLH-DSA-SHA2-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'sha2_192f':  Param{'SLH-DSA-SHA2-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'sha2_256s':  Param{'SLH-DSA-SHA2-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'sha2_256f':  Param{'SLH-DSA-SHA2-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
	// SHAKE-based family
	'shake_128s': Param{'SLH-DSA-SHAKE-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'shake_128f': Param{'SLH-DSA-SHAKE-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'shake_192s': Param{'SLH-DSA-SHAKE-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'shake_192f': Param{'SLH-DSA-SHAKE-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'shake_256s': Param{'SLH-DSA-SHAKE-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'shake_256f': Param{'SLH-DSA-SHAKE-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
}

// Kind is an enumeration type of the SLH-DSA key.
// See Table 2. SLH-DSA parameter sets of the Chapter 11. Parameter Sets
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

// kind_from_name make a Kind from name string
@[inline]
fn kind_from_name(name string) !Kind {
	match name {
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

// name returns the famous name of this Kind
@[inline]
fn (k Kind) name() string {
	match k {
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

// str returns string representation of this Kind k
@[inline]
fn (k Kind) str() string {
	match k {
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

// When 𝑙𝑔𝑤 = 4, 𝑤 = 16, 𝑙𝑒𝑛1 = 2𝑛, 𝑙𝑒𝑛2 = 3, and 𝑙𝑒𝑛 = 2𝑛 + 3.
// See FIPS 205 page 17
// w := uint32(1 << lgw)
const w = 16

@[inline]
fn (c &Context) wots_len() int {
	return 2 * c.prm.n + 3
}

@[inline]
fn (c &Context) wots_len1() int {
	return 2 * c.prm.n
}

@[inline]
fn (c &Context) wots_len2() int {
	return 3
}
