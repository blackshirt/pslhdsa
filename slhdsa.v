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
	randomize     bool
	deterministic bool
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
	c := new_context(k)
	// set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	skseed := rand.read(c.prm.n)!
	skprf := rand.read(c.prm.n)!
	pkseed := rand.read(c.prm.n)!

	return slh_keygen_with_seed(c, skseed, skprf, pkseed)!
}

// slh_keygen_with_seed generates a SLH-DSA key pair with the given seed values.
// The seed values must be non-zero to avoid weak keys.
@[direct_array_access; inline]
fn slh_keygen_with_seed(c &Context, skseed []u8, skprf []u8, pkseed []u8) !&SecretKey {
	// check if the seed is all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
		return error('seed is all zeroes')
	}
	return slh_keygen_internal(c, skseed, skprf, pkseed)!
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA key pair.
// Input: Secret seed SK.seed, PRF key SK.prf, public seed PK.seed
// Output: SLH-DSA key pair (SK, PK).
@[direct_array_access; inline]
fn slh_keygen_internal(c &Context, skseed []u8, skprf []u8, pkseed []u8) !&SecretKey {
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(c.prm.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pkroot := xmss_node(c, skseed, 0, u32(c.prm.hp), pkseed, mut addr)!
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	pk := &PubKey{
		ctx:  unsafe { c }
		seed: pkseed
		root: pkroot
	}
	return new_seckey_with_seed(c, skseed, skprf, pk)!
}

// new_seckey_with_seed returns a new secret key.
@[inline]
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
fn new_seckey_with_key(c &Context, key []u8) !&SecretKey {
	// check if the key is 4 * n bytes long
	if key.len != c.prm.n * 4 {
		return error('invalid secret key length')
	}
	// extract the secret key components from the key
	skseed := key[0..c.prm.n]
	skprf := key[c.prm.n..c.prm.n * 2]
	pkseed := key[c.prm.n * 2..c.prm.n * 3]
	// pkroot := key[c.prm.n*3..c.prm.n*4]

	// Generates step from keygen internal
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(c.prm.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pkroot := xmss_node(c, skseed, 0, u32(c.prm.hp), pkseed, mut addr)!
	// Check if the xmss_node function call was successful
	if pkroot.len != c.prm.n {
		return error('xmss_node failed')
	}

	// Check matching pk.root and provided part
	if subtle.constant_time_compare(pkroot, key[c.prm.n * 3..c.prm.n * 4]) != 1 {
		return error('mismatched public key root')
	}
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	pk := &PubKey{
		ctx:  unsafe { c }
		seed: pkseed
		root: pkroot
	}
	return new_seckey_with_seed(c, skseed, skprf, pk)!
}

// SLH-DSA signature data format
@[noinit]
struct SLHSignature {
mut:
	// n-bytes of randomness
	r []u8
	// 𝑘(1 + 𝑎) ⋅ 𝑛 bytes of FORS signature SIGFORS
	sigfors []u8
	// (ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 bytes of HT signature SIGHT,
	sight []u8
}

// bytes returns the signature bytes.
// The signature has a size of n + 𝑘(1 + 𝑎) ⋅ 𝑛 + (ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 bytes.
@[inline]
fn (s &SLHSignature) bytes() []u8 {
	mut out := []u8{cap: s.r.len + s.sigfors.len + s.sight.len}
	out << s.r
	out << s.sigfors
	out << s.sight

	return out
}

// 9.2 SLH-DSA Signature Generation
//
// Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
// Generates an SLH-DSA signature.
// Input: Message 𝑀, private key SK = (SK.seed, SK.prf, PK.seed, PK.root),
// (optional) additional random 𝑎𝑑𝑑𝑟𝑛𝑑
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn slh_sign_internal(msg []u8, sk &SecretKey, addrnd []u8) ![]u8 {
	// localizes some context variables for the signature generation
	outlen := sk.ctx.prm.n
	msize := sk.ctx.prm.m
	d := sk.ctx.prm.d
	k := sk.ctx.prm.k
	a := sk.ctx.prm.a
	h := sk.ctx.prm.h
	// Note: hp = h/d
	hp := sk.ctx.prm.hp

	// signature
	mut sig := []u8{cap: sk.ctx.prm.sigsize}

	// ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛, substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	mut opt_rand := addrnd.clone()

	// generate randomizer, 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
	r := sk.ctx.prf_msg(sk.prf, opt_rand, msg, outlen)!
	// SIG ← r
	sig << r

	// compute message digest, ie, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := sk.ctx.hmsg(r, sk.pk.seed, sk.pk.root, msg, msize)!

	// Intermediate values derived from the parameter sets
	// ceil [0 ∶ ⌈𝑘*𝑎⌉/8]
	ka8 := ((k * a) + 7) >> 3
	// ceil((h - (h/d))/8) ,  ⌈ℎ−ℎ/𝑑⌉ / 8, note hp = h/d
	hhd := ((h - hp) + 7) >> 3
	// ceil(h / 8d),   ⌈ℎ ⌈ 8𝑑 ⌉
	h8d := (hp + 7) >> 3

	// mut tmp_idxtree := []u8{len: 12}
	// mut tmp_idxleaf := []u8{len: 4}

	// first (𝑘⋅𝑎 ⌉ 8 ) bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ (𝑘⋅𝑎 ⌉ 8 )] [0 ∶ ⌈𝑘⋅𝑎8 ⌉ bytes 8 ⌉]
	md := digest[0..ka8]
	// mut start := ka8
	// mut innerstart := 12 - ka8

	// next, hhd bytes, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈(k*a)/8⌉ .. ⌈(k*a)/8⌉ + ∶ ⌈(h-h/d)/8⌉]
	// ∶ ⌈(k*a)/8⌉ .. ∶ ⌈(k*a)/8⌉ + ∶ ⌈(h-h/d)/8⌉
	tmp_idxtree := digest[ka8..ka8 + hhd]

	// next h8d bytes, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈(k*a)/8⌉ + ⌈(h-h/d)/8⌉ .. ⌈(k*a)/8⌉ + ⌈(h-h/d)/8⌉ + ⌈h/8d⌉]
	// ∶ ⌈(k*a)/8⌉ + ⌈(h-h/d)/8⌉ .. ∶ ⌈(k*a)/8⌉ + ⌈(h-h/d)/8⌉ + ⌈h/8d⌉
	tmp_idxleaf := digest[ka8 + hhd..ka8 + hhd + h8d]

	// ceil((h - (h/d))/8) ,  ⌈ℎ−ℎ/𝑑⌉ / 8, note hp = h/d
	idxtree_mask := (u64(1) << (h - hp)) - 1 // mod 2^(ℎ−ℎ/d)
	idxtree := to_int(tmp_idxtree, hhd) // & idxtree_mask

	// ceil(h / 8d),   ⌈ℎ ⌈ 8𝑑 ⌉
	idxleaf_mask := (u64(1) << hp) - 1 // mod 2^ℎ/d
	idxleaf := to_int(tmp_idxleaf, h8d) & idxleaf_mask

	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(idxtree)
	// ADRS.setTypeAndClear(FORS_TREE)
	addr.set_type_and_clear(.fors_tree)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_keypair_address(u32(idxleaf))

	// SIG𝐹𝑂𝑅𝑆 ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	sig_fors := fors_sign(sk.ctx, md, sk.seed, sk.pk.seed, mut addr)!
	// SIG ← SIG ∥ SIG𝐹𝑂𝑅s
	sig << sig_fors

	// get FORS key, PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pk_fors := fors_pkfromsig(sk.ctx, sig_fors, md, sk.pk.seed, mut addr)!
	// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹𝑂𝑅𝑆, SK.seed, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	sig_ht := ht_sign(sk.ctx, pk_fors, sk.seed, sk.pk.seed, idxtree, u32(idxleaf))!

	// : SIG ← SIG ∥ SIG𝐻t
	sig << sig_ht.bytes()
	// : return SIG
	return sig
}

/*
// 9.3 SLH-DSA Signature Verification
//
// Algorithm 20 slh_verify_internal(𝑀, SIG, PK)
// Verifies an SLH-DSA signature.
// Input: Message 𝑀, signature SIG, public key PK = (PK.seed, PK.root).
// Output: Boolean.
@[inline]
fn slh_verify_internal(c &Context, m []u8, sig &SLHSignature, pk &PubKey) !bool {
	// if |SIG| ≠ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 { return false }
	exp_length := (1 + c.k * (1 + c.a) + c.h + c.prm.d * c.wots_len()) * c.prm.n
	if sig.bytes().len != exp_length {
		return false
	}

	// ADRS ← toByte(0, 32)
	mut addr := new_address()
	// 𝑅 ← SIG.getR(), ▷ SIG[0 ∶ n]
	r := sig[0..c.prm.n].clone()
	// SIG𝐹𝑂𝑅𝑆 ← SIG.getSIG_FORS(), SIG[𝑛 ∶ (1 + 𝑘(1 + 𝑎)) ⋅ 𝑛]
	sig_fors := sig[c.prm.n..(1 + c.k * (1 + c.a)) * c.prm.n]
	// SIG𝐻𝑇 ← SIG.getSIG_HT(), SIG[(1 + 𝑘(1 + 𝑎)) ⋅ 𝑛 ∶ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛]
	sig_ht := sig[(1 + c.k * (1 + c.a)) * c.prm.n..(1 + c.k * (1 + c.a) + c.h + c.prm.d * c.wots_len()) * c.prm.n]	

	// compute message digest, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := c.hmsg(r, pk.seed, pk.root, msg, c.prm.m)!

	// first (k.a)/8 bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎)/8]
	md := digest[0..ka8]

	// next ⌈ℎ−ℎ/𝑑]/8 ⌉ bytes
	tmp_idxtree := digest[ka8..ka8 + hhd]

	// next [h/8𝑑] bytes
	tmp_idxleaf := digest[ka8 + hhd..ka8 + hhd + h8d]

	// ceil((h - (h/d))/8) ,  ⌈ℎ−ℎ/𝑑⌉ / 8, note hp = h/d
	idxtree_mask := u64(1 << (h - hp)) - 1 // mod 2^(ℎ−ℎ/d)
	idxleaf_mask := u64(1 << hp) - 1 // mod 2^(ℎ/d)	
	idxtree := to_int(tmp_idxtree, hhd) & idxtree_mask // mod 2^(ℎ−ℎ/d)
	idxleaf := to_int(tmp_idxleaf, h8d) & idxleaf_mask // mod 2^(ℎ/d)

	// compute FORS public key
	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	// ADRS.setTypeAndClear(FORS_TREE)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_tree_address(u64(idxtree))
	addr.set_type_and_clear(.fors_tree)
	addr.set_keypair_address(u32(idxleaf))

	// PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pk_fors := fors_pkfromsig(sk.ctx, sig_fors, md, pk.seed, mut addr)!

	// return ht_verify(c, pk_fors, sig_ht, pk.seed, idxtree, idxleaf, pk.root)!
	return ht_verify(sk.ctx, pk_fors, sig_ht, pk.seed, idxtree, idxleaf, pk.root)!		
}


const max_allowed_context_string = 255
// 10.2.1 Pure SLH-DSA Signature Generation
//
// Algorithm 22 slh_sign(𝑀, 𝑐𝑡𝑥, SK)
// Generates a pure SLH-DSA signature.
// Input: Message 𝑀, context string 𝑐𝑥, private key SK.
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn slh_sign(c &Context, m []u8, cx []u8, sk &SecretKey, opt SignerOpts) ![]u8 {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	mut addrnd := []u8{}
	if opt.randomize {
		addrnd = rand.read(c.n)!
	}

	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msg := []u8{}
	msg << to_bytes(0, 1)
	msg << to_bytes(u64(cx.len), 1)
	msg << cx
	msg << m

	// SIG ← slh_sign_internal(𝑀′, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(sk, msg, addrnd)!

	return sig
}


// 10.2.2 HashSLH-DSA Signature Generation
//
// Algorithm 23 hash_slh_sign(𝑀, 𝑐𝑡𝑥, PH, SK)
// Generates a pre-hash SLH-DSA signature.
// Input: Message 𝑀, context string 𝑐𝑡𝑥, pre-hash function PH, private key SK.
// Output: SLH-DSA signature SIG.
@[inline]
fn hash_slh_sign(c &Context, m []u8, cx []u8, ph crypto.Hash, sk &SecretKey, opt SignerOpts) ![]u8 {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	mut addrnd := []u8{}
	if opt.randomize {
		addrnd = rand.read(c.n)!
	}

	// default to sha256
	// OID ← toByte(0x0609608648016503040201, 11)
	mut oid := to_bytes(u64(0x0609608648016503040201), 11)
	// PH𝑀 ← SHA-256(𝑀 )
	mut phm := sha256.sum256(m)

	match ph {
		.sha256 {
			// do nothing
		}
		.sha512 {
			// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
			oid = to_bytes(u64(0x0609608648016503040203), 11)
			// PH𝑀 ← SHA-512(𝑀 )
			phm = sha512.sum512(m)
		}
		// need to be patched into .shake128
		.sha3_224 {
			// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
			oid = to_bytes(u64(0x060960864801650304020B), 11)
			// 17: PH𝑀 ← SHAKE128(𝑀, 256)
			phm = sha3.shake128(m, 256)
		}
		// // need to be patched into .shake256
		.sha3_256 {
			// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
			oid = to_bytes(u64(0x060960864801650304020C), 11)
			// PH𝑀 ← SHAKE256(𝑀, 512)
			phm = sha3.shake256(m, 512)
		}
		else {
			return error('Unsupported hash')
		}
	}

	// 𝑀′ ← toByte(1, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PHm
	mut msg := []u8{}
	msg << to_bytes(1, 1)
	msg << to_bytes(cx.len, 1)
	msg << cx
	msg << oid
	msg << phm

	// SIG ← slh_sign_internal(𝑀′, SK, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(sk.ctx, msg, sk, addrnd)!



	return sig
}


// 10.3 SLH-DSA Signature Verification
//
// Algorithm 24 slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PK)
// Verifies a pure SLH-DSA signature.
// Input: Message 𝑀, signature sig , context string 𝑐𝑡𝑥, public key PK.
// Output: Boolean.
@[inline]
fn slh_verify(c &Context, m []u8, sig []u8, cx []u8, p &PubKey) !bool {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msg := []u8{}
	msg << u8(0x00)
	msg << u8(cx.len)
	msg << cx
	msg << m

	// return slh_verify_internal(𝑀′, SIG, PK)
	return slh_verify_internal(c, msg, sig, p)!
}


// Algorithm 25 hash_slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PH, PK)
// Verifies a pre-hash SLH-DSA signature.
// Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK.
// Output: Boolean.
@[inline]
fn hash_slh_verify(c &Context, m []u8, sig []u8, cx []u8, ph crypto.Hash, p &PubKey) !bool {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// default to sha256
	// OID ← toByte(0x0609608648016503040201, 11)
	mut oid := to_bytes(u64(0x0609608648016503040201), 11)
	// PH𝑀 ← SHA-256(𝑀 )
	mut phm := sha256.sum256(m)

	match ph {
		.sha256 {
			// do nothing
		}
		.sha512 {
			// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
			oid = to_bytes(u64(0x0609608648016503040203), 11)
			// PH𝑀 ← SHA-512(𝑀 )
			phm = sha512.sum512(m)
		}
		// need to be patched into .shake128
		.sha3_224 {
			// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
			oid = to_bytes(u64(0x060960864801650304020B), 11)
			// 17: PH𝑀 ← SHAKE128(𝑀, 256)
			phm = sha3.shake128(m, 256)
		}
		// // need to be patched into .shake256
		.sha3_256 {
			// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
			oid = to_bytes(u64(0x060960864801650304020C), 11)
			// PH𝑀 ← SHAKE256(𝑀, 512)
			phm = sha3.shake256(m, 512)
		}
		else {
			return error('Unsupported hash')
		}
	}
	// 𝑀′ ← toByte(1, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PHm
	mut msg := []u8{}
	msg << u8(0x01)
	msg << u8(cx.len)
	msg << cx
	msg << oid
	msg << phm

	// return slh_verify_internal(𝑀′, SIG, PK)
	return slh_verify_internal(c, msg, sig, p)!
}
*/
