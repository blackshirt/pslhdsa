// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature module
module pslhdsa

import crypto
import crypto.rand
import crypto.sha256
import crypto.sha512
import crypto.sha3
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
	// validate the context string
	if cx.len > max_context_string_size {
		return error('cx must be at most max_context_string_size bytes long')
	}
	// Get the random value
	//
	// if deterministic was set, use the PK.seed as the random seed for deterministic signature
	// generation. if testing was set, use the entropy bytes as the random seed for testing purposes
	// otherwise, use the default crypto.rand.read for randomness
	opt_rand := if opt.deterministic {
		// use the public key seed as the random seed for deterministic signature generation
		s.pkseed
	} else if opt.testing {
		// use the testing entropy as the random seed for testing purposes
		if opt.entropy.len > max_entropy_size {
			return error('entropy must be at most max_entropy_size bytes long')
		}
		opt.entropy
	} else {
		// Hedged variant, use the random one by calling crypto.rand
		rand.read(s.ctx.prm.n)!
	}

	// gets the message encoding, the default is pure-hash SLH-DSA message encoding.
	//
	//
	msgout := if opt.msg_encoding == .pure {
		// pure hash message encoding, the default one
		encode_msg_purehash(cx, msg)
	} else {
		if opt.msg_encoding == .noencode {
			// Make sure testing flag is also set
			if !opt.testing {
				return error('testing not set for no_prehash feature')
			}
			// with this .noencode was set, the msg was not encoded.
			// NOTE: this features deviates from the FIPS 205 spec that
			// only support for pure-hash and pre-hash SLH-DSA generation.
			// USE WITH CAUTION!!
			msg
		} else {
			// pre-hashed message encoding
			// TODO: add supported hash algorithms into list
			if opt.hfunc !in supported_prehash_algo {
				return error('hfunc must be one of the supported prehash algorithms')
			}
			// get the ASN.1 DER serialized bytes for the hash oid
			oid := oid_for_hashfunc(opt.hfunc)!
			// pre-hashed message with hfunc
			phm := phm_for_hashfunc(opt.hfunc, msg)!

			// pre-hash message encoding
			encode_msg_prehash(cx, oid, phm)
		}
	}

	// use slh_sign_internal to generate the signature
	sig := slh_sign_internal(msgout, s, opt_rand)!

	return sig.bytes()
}

// default maximum of additional randomness size, 2048 bytes.
const max_entropy_size = 2048

// supported_prehash_algo is a list of supported prehash algorithms in pre-hash message encoding
const supported_prehash_algo = [crypto.Hash.sha256, .sha512, .md4, .md5]

// Options is an options struct for SLH-DSA operation, includes key generation,
// signature generation and signature verification.
@[params]
pub struct Options {
pub mut:
	// check_pk flag was used in SLH-DSA key generation, especially in `slh_keygen_from_bytes`
	// to check if the public key root is valid in SLH-DSA key generation.
	// If set to true, it will check if the public key root is valid.
	// If set to false, it will not check the public key root and maybe fails on
	// signature verification, default to true.
	check_pk bool = true

	// The option below was used in signature generation.
	//
	// deterministic signature generation, where the randomness is replaced by sk.pkseed.
	// default to false and use crypto.rand.read for randomness.
	deterministic bool

	// testing flag for testing or advanced purposes. if set to true, it will use entropy bytes
	// as a random values pass to internal signing process. When deterministic flag is set,
	// it will be ignored.
	testing bool

	// entropy is an additional randomness value, only for non-deterministic signature testing.
	// the testing flag should be set to true to enable this option.
	// the entropy size must be at most max_entropy_size bytes long.
	entropy []u8

	// msg_encoding defines the way of message encoding for signature generation (verication)
	// was performed. The default value .pure means for 'Pure SLH-DSA Signature Generation (verification)'.
	// .pre for 'Pre Hash SLH-DSA Signature Generation (verification)' or .noencode for not encode the mesage behaviour,
	// .noencode was intended for testing. If not sure, just use the default .pure value.
	msg_encoding MsgEncoding = .pure

	// hfunc is the hash function used in pre-hashed message encoding,
	// used only when msg_encoding is false. The default value is sha256.
	hfunc crypto.Hash = .sha256
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
	// check for context string size
	if cx.len > max_context_string_size {
		return error('cx must be at most max_context_string_size bytes long')
	}
	// Parse signature bytes into SLHSignature opaque
	slh_sig := parse_slhsignature(p.ctx, sig)!

	// gets the message encoding, the default is pure-hash SLH-DSA message encoding.
	//
	msgout := if opt.msg_encoding == .pure {
		// pure hash message encoding, the default one
		encode_msg_purehash(cx, msg)
	} else {
		if opt.msg_encoding == .noencode {
			// Make sure testing flag is also set
			if !opt.testing {
				return error('testing not set for noencode feature')
			}
			// with this noencode was set, the msg was not encoded.
			// NOTE: this features deviates from the FIPS 205 spec that
			// only support for pure-hash and pre-hash SLH-DSA generation.
			// USE WITH CAUTION!!
			msg
		} else {
			// pre-hashed message encoding
			// TODO: add supported hash algorithms into list
			if opt.hfunc !in supported_prehash_algo {
				return error('hfunc must be one of the supported prehash algorithms')
			}
			// get the ASN.1 DER serialized bytes for the hash oid
			oid := oid_for_hashfunc(opt.hfunc)!
			// pre-hashed message with hfunc
			phm := phm_for_hashfunc(opt.hfunc, msg)!

			// pre-hash message encoding
			encode_msg_prehash(cx, oid, phm)
		}
	}
	return slh_verify_internal(msgout, slh_sig, p)!
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

	// 	calculated length of the signature
	clength := n + k * (1 + a) * n + (h + d * len) * n
	if bytes.len != clength {
		return error('signature bytes must correct size for ${c.kind}')
	}
	r := bytes[0..n]
	fors := bytes[n..n + k * (1 + a) * n]
	// relaxed length size to the end of the bytes,
	// so that the hypertree signature can handle this.
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

// Message encoding
//
const me_null = u8(0)
const me_ones = u8(1)

pub enum MsgEncoding {
	// Pure SLH-DSA hash message encoding construct
	pure
	// Pre-hash SLH-DSA message encoding construct
	pre
	// No encode message encoding
	noencode
}

// encode_msg_purehash combines the message components into a single message.
// The message is encoded as per the SLH-DSA specification, section 10.2.1.
// See on 10.2.1 Pure SLH-DSA Signature Generation
@[direct_array_access; inline]
fn encode_msg_purehash(cx []u8, msg []u8) []u8 {
	// 𝑀′ ← toByte(me, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msgout := []u8{cap: 2 + cx.len + msg.len}
	// to_byte(0, 1)
	msgout << me_null
	// to_byte(|𝑐𝑡𝑥|, 1), |𝑐𝑡𝑥| should fit in 1-byte
	msgout << u8(cx.len)
	msgout << cx
	msgout << msg

	return msgout
}

// encode_msg_prehash combines the message components into a single message.
// The message is encoded as per the SLH-DSA specification, section 10.2.2.
// See on 10.2.2 HashSLH-DSA Signature Generation
@[direct_array_access; inline]
fn encode_msg_prehash(cx []u8, oid []u8, phm []u8) []u8 {
	// 𝑀′ ← toByte(1, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PHm
	mut msgout := []u8{cap: 2 + cx.len + oid.len + phm.len}
	// to_byte(1, 1)
	msgout << me_ones
	// to_byte(|𝑐𝑡𝑥|, 1), |𝑐𝑡𝑥| should fit in 1-byte
	msgout << u8(cx.len)
	msgout << cx
	// underlying ASN.1 DER serialized OID
	msgout << oid
	// pre-hashed message
	msgout << phm

	return msgout
}

// oid_for_hashfunc returns the serialized OID for the given hash function.
// If the hash function is not supported, it return error.
@[inline]
fn oid_for_hashfunc(hfunc crypto.Hash) ![]u8 {
	return match hfunc {
		.sha256 { oid_sha256 }
		.sha512 { oid_sha512 }
		.md4 { oid_shake128 }
		.md5 { oid_shake256 }
		else { return error('unsupported hash function') }
	}
}

// phm_for_hashfunc returns the pre-hashed message for the given hash function.
// If the hash function is not supported, it returns an error.
@[inline]
fn phm_for_hashfunc(hfunc crypto.Hash, msg []u8) ![]u8 {
	return match hfunc {
		.sha256 {
			// PH𝑀 ← SHA-256(𝑀)
			return sha256.sum256(msg)
		}
		.sha512 {
			// PH𝑀 ← SHA-512(𝑀)
			return sha512.sum512(msg)
		}
		.md4 {
			// 17: PH𝑀 ← SHAKE128(𝑀, 256), 32-bytes
			return sha3.shake128(msg, 32)
		}
		.md5 {
			// PH𝑀 ← SHAKE256(𝑀, 512), 64-bytes
			return sha3.shake256(msg, 64)
		}
		else {
			return error('unsupported hash function')
		}
	}
}

// OID of SHA256 : 2.16.840.1.101.3.4.2.1
// OID ← toByte(0x0609608648016503040201, 11)
const oid_sha256 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]

// OID of SHA512 : 2.16.840.1.101.3.4.2.3
// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
const oid_sha512 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]

// OID of SHAKE128 : 2.16.840.1.101.3.4.2.11
// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
const oid_shake128 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B]

// OID of SHAKE256 : 2.16.840.1.101.3.4.2.12
// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
const oid_shake256 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C]

// (OID) for SHA-512/224 (2.16.840.1.101.3.4.2.5)
const oid_sha512_224 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05]

// (OID) for SHA-512/256 (2.16.840.1.101.3.4.2.6)
// 06 09 60 86 48 01 65 03 04 02 06
const oid_sha512_256 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06]

// (OID) for SHA-384 is 2.16.840.1.101.3.4.2.2
// 06 09 60 86 48 01 65 03 04 02 02
const oid_sha384 = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]

// OID for SHA2-224 (1.2.840.113549.1.1.14)
// 060b2a864886f70d01010e
const oid_sha2_224 = [u8(0x06), 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e]
