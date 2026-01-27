// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature module
module pslhdsa

import crypto.rand
import crypto.internal.subtle

const default_context = new_context(.sha2_128f)

// The SLH-DSA Private Key
//
// The private key contains two random, secret 𝑛-byte values (see Figure 15). SK.seed is
// used to generate all of the WOTS+ and FORS private key elements. SK.prf is used to generate a
// randomization value for the randomized hashing of the message in SLH-DSA. The private key
// also includes a copy of the public key components.
// The private key has a size of 4 * n bytes, which includes the public key components.
// i.e. It consists of the concatenation of SK.seed, SK.prf, PK.seed and PF.root
@[noinit]
struct SecretKey {
mut:
	// associated context of the secret key
	ctx &Context
	// secret seed of the secret key
	seed []u8
	// secret PRF of the secret key
	prf []u8
	// public key components of the secret key
	pk &PubKey
}

// bytes returns the private key bytes.
// The private key has a size of 4 * n bytes, which includes the public key components.
// i.e. It consists of the concatenation of SK.seed, SK.prf, PK.seed and PF.root
@[inline]
fn (s &SecretKey) bytes() []u8 {
	mut out := []u8{cap: s.ctx.prm.n * 4}
	out << s.seed
	out << s.prf
	out << s.pk.seed
	out << s.pk.root

	return out
}

// pubkey returns the public key.
@[inline]
fn (s &SecretKey) pubkey() &PubKey {
	return s.pk
}

// SLH-DSA Public Key
//
// The public keys contain two elements. The first is an 𝑛-byte public seed
// PK.seed, which is used in many hash function calls to provide domain separation between
// different SLH-DSA key pairs. The second value is the hypertree public key (i.e., the root of the
// top layer XMSS tree).
// The public key has a size of 2 * n bytes. i.e. It consists of the concatenation of PK.seed and PK.root
@[noinit]
struct PubKey {
mut:
	// associated context of the public key, should equal to the context of the secret key
	// where the public key is bind to the secret key
	ctx &Context
	// public seed of the public key
	seed []u8
	// public root of the public key	
	root []u8
}

// bytes returns the public key bytes. The public key has a size of 2 * n bytes.
// i.e. It consists of the concatenation of PK.seed and PK.root
@[inline]
fn (p &PubKey) bytes() []u8 {
	mut out := []u8{cap: p.ctx.prm.n * 2}
	out << p.seed
	out << p.root

	return out
}

@[params]
struct SignerOpts {
mut:
	// deterministic signature generation
	deterministic bool
	// use random seed for signature generation
	randomize bool
	// use this random seed for signature generation
	addrnd []u8 // ctx.prm.n length	
}

// 10.1 SLH-DSA Key Generation
//
// Algorithm 21 slh_keygen()
// Generates an SLH-DSA key pair.
// Input: (none)
// Output: SLH-DSA secret key
// slh_keygen generates a SLH-DSA key with the given kind.
@[inline]
fn slh_keygen(k Kind) !&SecretKey {
	// create a new context for the key generation
	ctx := new_context(k)
	// set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	skseed := rand.read(ctx.prm.n)!
	skprf := rand.read(ctx.prm.n)!
	pkseed := rand.read(ctx.prm.n)!

	return slh_keygen_with_seed(ctx, skseed, skprf, pkseed)!
}

// slh_keygen_with_seed generates a SLH-DSA key pair with the given seed values.
// The seed values must be non-zero to avoid weak keys.
@[direct_array_access; inline]
fn slh_keygen_with_seed(ctx &Context, skseed []u8, skprf []u8, pkseed []u8) !&SecretKey {
	// check if the seed is all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
		return error('seed is all zeroes')
	}
	return slh_keygen_internal(ctx, skseed, skprf, pkseed)!
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA key pair.
// Input: Secret seed SK.seed, PRF key SK.prf, public seed PK.seed
// Output: SLH-DSA key pair (SK, PK).
@[direct_array_access; inline]
fn slh_keygen_internal(ctx &Context, skseed []u8, skprf []u8, pkseed []u8) !&SecretKey {
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(ctx.prm.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pkroot_node := xmss_node(ctx, skseed, 0, u32(ctx.prm.hp), pkseed, mut addr)!
	// Check if the xmss_node function call was successful
	if pkroot_node.len != ctx.prm.n {
		return error('xmss_node failed')
	}
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	pk := &PubKey{
		ctx:  unsafe { ctx }
		seed: pkseed
		root: pkroot_node
	}
	return new_seckey_with_seed(ctx, skseed, skprf, pk)!
}

// new_seckey_with_seed returns a new secret key.
@[direct_array_access; inline]
fn new_seckey_with_seed(ctx &Context, seed []u8, prf []u8, pk &PubKey) !&SecretKey {
	// check if the context of the secret key and the given public key are equal
	if !ctx.equal(pk.ctx) {
		return error('context of the secret key and the public key are not equal')
	}
	// check if the seed or PRF values are all zeroes, which could indicate a weak key
	if is_zero(seed) || is_zero(prf) {
		return error('weak secret key')
	}
	// check the length of the secret key components
	if seed.len != ctx.prm.n || prf.len != ctx.prm.n || pk.seed.len != ctx.prm.n
		|| pk.root.len != ctx.prm.n {
		return error('invalid secret key length')
	}
	return &SecretKey{
		ctx:  unsafe { ctx }
		seed: seed
		prf:  prf
		pk:   unsafe { pk }
	}
}

// new_seckey_with_key returns a new secret key with the given key.
// The key must be 4 * n bytes long.
@[direct_array_access; inline]
fn new_seckey_with_key(ctx &Context, key []u8) !&SecretKey {
	// check if the key is 4 * n bytes long
	if key.len != ctx.prm.n * 4 {
		return error('invalid secret key length')
	}
	// extract the secret key components from the key
	skseed := key[0..ctx.prm.n]
	skprf := key[ctx.prm.n..2 * ctx.prm.n]
	pkseed := key[2 * ctx.prm.n..3 * ctx.prm.n]
	pkroot := key[3 * ctx.prm.n..4 * ctx.prm.n]

	// Generates step from keygen internal
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(ctx.prm.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pkroot_node := xmss_node(ctx, skseed, 0, u32(ctx.prm.hp), pkseed, mut addr)!
	// Check if the xmss_node function call was successful
	if pkroot_node.len != ctx.prm.n {
		return error('xmss_node failed')
	}

	// Check matching pk.root and provided part
	if subtle.constant_time_compare(pkroot, pkroot_node) != 1 {
		return error('mismatched public key root')
	}
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	pk := &PubKey{
		ctx:  unsafe { ctx }
		seed: pkseed
		root: pkroot_node
	}
	return new_seckey_with_seed(ctx, skseed, skprf, pk)!
}

// SLH-DSA signature data format
@[noinit]
struct SLHSignature {
mut:
	// n-bytes of randomness
	r []u8
	// 𝑘(1 + 𝑎) ⋅ 𝑛 bytes of FORS signature SIGFORS
	fors []u8
	// (ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 bytes of HT signature HT,
	ht &HypertreeSignature
}

// bytes returns the signature bytes.
// The signature has a size of n + 𝑘(1 + 𝑎) ⋅ 𝑛 + (ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 bytes.
@[inline]
fn (s &SLHSignature) bytes() []u8 {
	ht := s.ht.bytes()
	size := s.r.len + s.fors.len + ht.len
	mut out := []u8{cap: size}
	out << s.r
	out << s.fors
	out << ht

	return out
}
