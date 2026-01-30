// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature module
module pslhdsa

import crypto.internal.subtle

const max_context_string_size = 255

// the default context used by this SLH-DSA module. it uses the SHA-2 128f hash function
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
pub struct SigningKey {
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

// sign signs the message msg with the signing key s.
// The context string cx must be at most max_context_string_size bytes long.
@[direct_array_access]
pub fn (s &SigningKey) sign(msg []u8, cx []u8, opt Options) ![]u8 {
	if cx.len > max_context_string_size {
		return error('cx must be at most max_context_string_size bytes long')
	}
	match opt.deterministic {
		true {
			// deterministic variant, opt_rand == s.pkseed
			opt_rand := s.pkseed.clone()
			match opt.msg_encoding {
				.purehash {
					// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
					msgout := compose_msg_purehash(cx, msg)
					// SIG ← slh_sign_internal(msgout []u8, sk &SigningKey, addrnd []u8) !&SLHSignature
					sig := slh_sign_internal(msgout, s, opt_rand)!
					return sig.bytes()
				}
				.prehash {
					return error('preHash variant is not supported for deterministic variant')
				}
				.nohash {
					return error('nohash variant is not supported for deterministic variant')
				}
			}
		}
		false {
			// non-deterministic variant
			match opt.testing {
				true {
					// testing variant, opt_rand == opt.entropy
					opt_rand := opt.entropy.clone()
				}
				false {
					// non-testing variant, opt_rand == s.prf
					opt_rand := s.prf.clone()
				}
			}
			match opt.msg_encoding {
				.purehash {}
				.prehash {
					return error('preHash variant is not supported for non-deterministic variant')
				}
				.nohash {
					return error('nohash variant is not supported for non-deterministic variant')
				}
			}
		}
	}
}

// SLH-DSA Public Key
//
// The public keys contain two elements. The first is an 𝑛-byte public seed
// PK.seed, which is used in many hash function calls to provide domain separation between
// different SLH-DSA key pairs. The second value is the hypertree public key (i.e., the root of the
// top layer XMSS tree).
// The public key has a size of 2 * n bytes. i.e. It consists of the concatenation of PK.seed and PK.root
@[noinit]
pub struct PubKey {
mut:
	// associated context of the public key, should equal to the context of the secret key
	// where the public key is bind to the secret key
	ctx &Context
	// public seed of the public key
	seed []u8
	// public root of the public key	
	root []u8
}

// new_pubkey creates a new public key with the given context and bytes.
// The bytes must be ctx.prm.n * 2 bytes long. Its also check if the seed and root
// components are all zeroes that unallowed in this module. If so, it returns an error.
@[direct_array_access]
pub fn new_pubkey(ctx &Context, bytes []u8) !&PubKey {
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

// verify verifies the signature of the message msg against the public key p.
// The context string cx must be at most max_context_string_size bytes long.
@[direct_array_access]
pub fn (p &PubKey) verify(msg []u8, sig []u8, cx []u8, opt Options) !bool {
	if cx.len > max_context_string_size {
		return error('cx must be at most max_context_string_size bytes long')
	}
	return error('not implemented')
}

// default maximum of additional randomness size, 2048 bytes.
const max_entropy_size = 2048

// Options is an options struct for SLH-DSA operation, includes key generation,
// signature generation and verification options.
@[params]
pub struct Options {
pub mut:
	// check_pk flag was used in `slh_keygen_from_bytes` to check if the public key root
	// is valid in SLH-DSA key generation.
	// If set to true, it will check if the public key root is valid.
	// If set to false, it will not check the public key root and maybe fails on
	// signature verification, default to true.
	check_pk bool = true

	// The option below was used in signature generation.
	//
	// deterministic signature generation, where the randomness is replaced by sk.pkseed.
	// default to false and use crypto.rand.read for randomness.
	deterministic bool

	// msg_encoding defines the way signature generation was performed.
	// The default value .purehash means for 'Pure SLH-DSA Signature Generation'.
	// Setting it to .prehash does not encode the message, which is used for testing,
	// but can also be used for 'Pre Hash SLH-DSA Signature Generation'.
	msg_encoding MsgEncoding = .purehash

	// hfunc is the hash function used in signature generation, used only when msg_encoding is .prehash.
	// The default value is sha3.shake256.
	hfunc crypto.Hash = .shake256

	// testing flag for testing purposes. if set to true, it will use entropy bytes
	// as a random values pass to internal signing process. when deterministic is set,
	// it will be ignored.
	testing bool

	// entropy is an additional randomness, only for non-deterministic signature testing.
	// the testing flag should be set to true to enable this option.
	// entropy must be at most max_entropy_size bytes long.
	entropy []u8
}

// the way signature generation is applied.
pub enum MsgEncoding {
	// default, pure SLH-DSA signature generation
	purehash
	// pre-hash SLH-DSA signature generation
	prehash
	// no-hash SLH-DSA signature generation, non-standard
	// NOTE: DONT USE THIS
	nohash
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

// parse_slhsignature parses the SLH-DSA signature from the given bytes.
// The bytes must be ctx.prm.n + ctx.prm.k * (1 + ctx.prm.a) * ctx.prm.n + (ctx.prm.h + ctx.prm.d * ctx.prm.len) * ctx.prm.n bytes long.
// If not, it returns an error.
@[direct_array_access; inline]
fn parse_slhsignature(c &Context, bytes []u8) !&SLHSignature {
	k := c.prm.k
	a := c.prm.a
	n := c.prm.n
	h := c.prm.h
	d := c.prm.d
	len := c.wots_len()

	// calculated length of the signature
	clength := n + k * (1 + a) * n + (h + d * len) * n
	if bytes.len != clength {
		return error('bytes must correct size for ${c.kind}')
	}
	r := bytes[0..n]
	fors := bytes[n..n + k * (1 + a) * n]
	ht := parse_hypertree(c, bytes[n + k * (1 + a) * n..clength])!
	return &SLHSignature{
		r:    r
		fors: fors
		ht:   ht
	}
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
