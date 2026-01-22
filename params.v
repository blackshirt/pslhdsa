// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Parameter Set
module pslhdsa

import crypto.sha3
import crypto.sha256
import cyrpto.sha512

@[noinit]
struct SlhContext {
mut:
	kind   Kind
	psfunc PsFuncs
	prm    Param
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

// Table 2. SLH-DSA parameter sets
const paramset = {
	// 						     			id   𝑛  ℎ   𝑑  ℎp  𝑎  𝑘  𝑙𝑔𝑤 𝑚 sc pklen  siglen
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
// PsFuncs is a hashing and or pseudorandom functions used in the mean time of SLH-DSA operation.
interface PsFuncs {
	// pseudorandom function (PRF) that generates the randomizer (𝑅)
	// for the randomized hashing of the message to be signed
	prf_msg(sk_prf []u8, opt_rand []u8, msg []u8, outlen int) []u8
	// hmsg was used to generate the digest of the message to be signed.
	hmsg(r []u8, pk_seed []u8, pk_root []u8, msg []u8, outlen int) []u8
	// prf is a pseudorandom function  (PRF) that is used to generate the secret values
	// in WOTS+ and FORS private keys.
	prf(pk_seed []u8, sk_seed []u8, adrs Address, outlen int) []u8
	// tlhash is a hash function that maps an ℓ𝑛-byte message to an 𝑛-byte message.
	tlhash(pk_seed []u8, adrs Address, ml [][]u8, outlen int) []u8
	// hhash is a special case of Tℓ that takes a 2𝑛-byte message as input.
	hhash(pk_seed []u8, adrs Address, m2 []u8, outlen int) []u8
	// fhash is a hash function that takes an 𝑛-byte message as input and produces an 𝑛-byte output.
	fhash(pk_seed []u8, adrs Address, m1 []u8, outlen int) []u8
}

// SHAKE based Parameter Set
// See 11.1 SLH-DSA Using SHAKE
struct ShakePs {}

@[direct_array_access]
fn (s ShakePs) prf_msg(sk_prf []u8, opt_rand []u8, msg []u8, outlen int) []u8 {
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)
	mut data := []u8{cap: sk_prf.len + opt_rand.len + msg.len}

	data << sk_prf
	data << opt_rand
	data << msg

	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s ShakePs) hmsg(r []u8, pk_seed []u8, pk_root []u8, msg []u8, outlen int) []u8 {
	size := r.len + pk_seed.len + pk_root.len + msg.len
	mut data := []u8{cap: size}
	data << r
	data << pk_seed
	data << pk_root
	data << m
	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s ShakePs) prf(pk_seed []u8, sk_seed []u8, adrs Address, outlen int) []u8 {
	// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)
	// adrs.bytes() = =32
	size := pk_seed.len + sk_seed.len + 32 + sk_seed.len
	mut data := []u8{cap: size}
	data << pk_seed
	data << addr.bytes()
	data << sk_seed
	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s ShakePs) tlhash(pk_seed []u8, adrs Address, m1 [][]u8, outlen int) []u8 {
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)
	mut m1size := 0
	for o in m1 {
		m1size += o.len
	}
	size := pk_seed.len + 32 + m1size
	mut data := []u8{cap: size}
	data << pk_seed
	data << addr.bytes()
	for item in m1 {
		data << item
	}

	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s ShakePs) hhash(pk_seed []u8, adrs Address, m2 []u8, outlen int) []u8 {
	// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
	mut data := []u8{cap: pk_seed.len + 32 + m2.len}
	data << pk_seed
	data << addr.bytes()
	data << m2

	return sha3.shake256(data, outlen)
}

@[direct_array_access]
fn (s ShakePs) fhash(pk_seed []u8, adrs Address, m1 []u8, outlen int) []u8 {
	// F(PK.seed, ADRS, 𝑀1) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)
	mut data := []u8{cap: pk_seed.len + 32 + m1.len}
	data << pk_seed
	data << addr.bytes()
	data << m1

	return sha3.shake256(data, outlen)
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
