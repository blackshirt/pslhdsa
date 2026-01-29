// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature module
module pslhdsa

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
struct SigningKey {
mut:
	// associated context of the signing key
	ctx &Context
	// private seed value
	seed []u8
	// PRF key value
	prf []u8
	// public seed value
	pkseed []u8
	// public root value
	pkroot []u8
}

// new_signing_key creates a new signing key with the given context and seed.
// The seed must be ctx.prm.n bytes long.
// If not, it returns an error.
@[inline]
fn new_signing_key(c &Context, seed []u8) !&SigningKey {
	if seed.len != 4 * c.prm.n {
		return error('seed must be 4*ctx.prm.n bytes long')
	}
	skseed := seed[0..c.prm.n]
	skprf := seed[c.prm.n..c.prm.n * 2]
	pkseed := seed[c.prm.n * 2..c.prm.n * 3]
	pkroot := seed[c.prm.n * 3..c.prm.n * 4]
	// check if the seed components are all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) || is_zero(pkroot) {
		return error('seed components are all zeroes')
	}

	return &SigningKey{
		ctx:    unsafe { c }
		seed:   skseed
		prf:    skprf
		pkseed: pkseed
		pkroot: pkroot
	}
}

// bytes returns the signing key bytes.
// The signing key has a size of 4 * n bytes, which includes the public key components.
// i.e. It consists of the concatenation of SK.seed, SK.prf, PK.seed and PF.root
@[inline]
pub fn (s &SigningKey) bytes() []u8 {
	mut out := []u8{cap: s.ctx.prm.n * 4}
	out << s.seed
	out << s.prf
	out << s.pkseed
	out << s.pkroot

	return out
}

// pubkey returns the public key.
@[inline]
pub fn (s &SigningKey) pubkey() &PubKey {
	return &PubKey{
		ctx:  unsafe { s.ctx }
		seed: s.pkseed
		root: s.pkroot
	}
}

// equal returns true if the signing key is equal to the other signing key.
@[inline]
pub fn (s &SigningKey) equal(o &SigningKey) bool {
	return s.ctx.equal(o.ctx) && subtle.constant_time_compare(s.seed, o.seed) == 1
		&& subtle.constant_time_compare(s.prf, o.prf) == 1
		&& subtle.constant_time_compare(s.pkseed, o.pkseed) == 1
		&& subtle.constant_time_compare(s.pkroot, o.pkroot) == 1
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

// new_pubkey creates a new public key with the given context, seed, and root.
// The seed and root must be ctx.prm.n bytes long.
// If not, it returns an error.
@[inline]
fn new_pubkey(ctx &Context, bytes []u8) !&PubKey {
	if bytes.len != ctx.prm.n * 2 {
		return error('bytes must be ctx.prm.n * 2 bytes long')
	}
	seed := bytes[0..ctx.prm.n]
	root := bytes[ctx.prm.n..ctx.prm.n * 2]
	// check if the seed and root are all zeroes
	if is_zero(seed) || is_zero(root) {
		return error('seed and root components are all zeroes')
	}
	return &PubKey{
		ctx:  unsafe { ctx }
		seed: seed
		root: root
	}
}

// bytes returns the public key bytes. The public key has a size of 2 * n bytes.
// i.e. It consists of the concatenation of PK.seed and PK.root
@[inline]
pub fn (p &PubKey) bytes() []u8 {
	mut out := []u8{cap: p.ctx.prm.n * 2}
	out << p.seed
	out << p.root

	return out
}

// equal returns true if the public key is equal to the other public key.
@[inline]
pub fn (p &PubKey) equal(o &PubKey) bool {
	return p.ctx.equal(o.ctx) && subtle.constant_time_compare(p.seed, o.seed) == 1
		&& subtle.constant_time_compare(p.root, o.root) == 1
}

@[params]
struct SignerOpts {
mut:
	// deterministic signature generation
	deterministic bool
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
