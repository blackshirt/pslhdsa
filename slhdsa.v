// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature module
module pslhdsa

import crypto
import crypto.rand
import crypto.sha3
import crypto.sha256
import crypto.sha512
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

// slh_sign_internal_deterministic generates a deterministic SLH-DSA signature.
@[direct_array_access; inline]
fn slh_sign_internal_deterministic(msg []u8, sk &SecretKey) !&SLHSignature {
	// use the public key seed as the random seed for deterministic signature generation
	addrnd := sk.pk.seed.clone()
	return slh_sign_internal(msg, sk, addrnd)!
}

// 9.2 SLH-DSA Signature Generation
//
// Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
// Generates an SLH-DSA signature.
// Input: Message 𝑀, private key SK = (SK.seed, SK.prf, PK.seed, PK.root),
// (optional) additional random 𝑎𝑑𝑑𝑟𝑛𝑑
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn slh_sign_internal(msg []u8, sk &SecretKey, addrnd []u8) !&SLHSignature {
	// localizes some context variables for the signature generation
	outlen := sk.ctx.prm.n
	msize := sk.ctx.prm.m
	// d := sk.ctx.prm.d
	k := sk.ctx.prm.k
	a := sk.ctx.prm.a
	h := sk.ctx.prm.h
	// Note: hp = h/d
	hp := sk.ctx.prm.hp

	// signature

	// ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛, substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	mut opt_rand := addrnd.clone()

	// generate randomizer, 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
	r := sk.ctx.prf_msg(sk.prf, opt_rand, msg, outlen)!
	// SIG ← r

	// compute message digest, ie, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := sk.ctx.hmsg(r, sk.pk.seed, sk.pk.root, msg, msize)!

	// Intermediate values derived from the parameter sets
	// ceil [0 ∶ ⌈𝑘*𝑎⌉/8]
	ka8 := ((k * a) + 7) >> 3
	// ceil((h - (h/d))/8) ,  ⌈ℎ−ℎ/𝑑⌉ / 8, note hp = h/d
	hhd := (h - hp + 7) >> 3
	// ceil(h / 8d),   ⌈ℎ ⌈ 8𝑑 ⌉
	h8d := (hp + 7) >> 3

	mut tmp_idxtree := []u8{len: 12}
	mut tmp_idxleaf := []u8{len: 4}

	// first (𝑘⋅𝑎 ⌉ 8 ) bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ (𝑘⋅𝑎 ⌉ 8 )] [0 ∶ ⌈𝑘⋅𝑎8 ⌉ bytes 8 ⌉]
	md := digest[0..ka8]

	// splitting digest into idxTree and idxLeaf
	mut start := ka8
	mut innerstart := 12 - hhd
	mut stop := ka8 + hhd

	copy(mut tmp_idxtree[innerstart..], digest[start..stop])
	start += hhd
	stop = start + h8d
	innerstart = 4 - h8d
	copy(mut tmp_idxleaf[innerstart..], digest[start..stop])

	idxtree := make_treeindex(tmp_idxtree, hhd).mod_2b(h - hp)
	idxleaf := u32(to_int(tmp_idxleaf, 4)) & ((1 << hp) - 1)

	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(idxtree)
	// ADRS.setTypeAndClear(FORS_TREE)
	addr.set_type_and_clear(.fors_tree)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_keypair_address(idxleaf)

	// SIG𝐹𝑂𝑅𝑆 ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	fors := fors_sign(sk.ctx, md, sk.seed, sk.pk.seed, mut addr)!
	// SIG ← SIG ∥ SIG𝐹𝑂𝑅s

	// get FORS key, PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pkfors := fors_pkfromsig(sk.ctx, fors, md, sk.pk.seed, mut addr)!
	// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹𝑂𝑅𝑆, SK.seed, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	mut idxtree_c := idxtree.clone()
	ht := ht_sign(sk.ctx, pkfors, sk.seed, sk.pk.seed, mut idxtree_c, idxleaf)!

	// : SIG ← SIG ∥ SIG𝐻𝑇

	// : return SIG
	sig := &SLHSignature{
		r:    r
		fors: fors
		ht:   ht
	}
	return sig
}

// 9.3 SLH-DSA Signature Verification
//
// Algorithm 20 slh_verify_internal(𝑀, SIG, PK)
// Verifies an SLH-DSA signature.
// Input: Message 𝑀, signature SIG, public key PK = (PK.seed, PK.root).
// Output: Boolean.
@[direct_array_access; inline]
fn slh_verify_internal(msg []u8, sig &SLHSignature, pk &PubKey) !bool {
	n := pk.ctx.prm.n
	a := pk.ctx.prm.a
	k := pk.ctx.prm.k
	m := pk.ctx.prm.m
	h := pk.ctx.prm.h
	hp := pk.ctx.prm.hp
	length := pk.ctx.wots_len()

	// if |SIG| ≠ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ length) ⋅ 𝑛 { return false }
	exp_length := (1 + k * (1 + a) + h + hp * length) * n
	if sig.bytes().len != exp_length {
		return false
	}

	// Intermediate values derived from the parameter sets
	// ceil [0 ∶ ⌈𝑘*𝑎⌉/8]
	ka8 := ((k * a) + 7) >> 3
	// ceil((h - (h/d))/8) ,  ⌈ℎ−ℎ/𝑑⌉ / 8, note hp = h/d
	hhd := (h - hp + 7) >> 3
	// ceil(h / 8d),   ⌈ℎ ⌈ 8𝑑 ⌉
	h8d := (hp + 7) >> 3

	// ADRS ← toByte(0, 32)
	mut addr := new_address()
	// 𝑅 ← SIG.getR(), ▷ SIG[0 ∶ n]
	// r := sig[0..n].clone()
	// SIG𝐹𝑂𝑅𝑆 ← SIG.getsigfors(), SIG[𝑛 ∶ (1 + 𝑘(1 + 𝑎)) ⋅ 𝑛]
	// fors := sig[n..(1 + k * (1 + a)) * n]
	// SIG𝐻𝑇 ← SIG.getht(), SIG[(1 + 𝑘(1 + 𝑎)) ⋅ 𝑛 ∶ (1 + 𝑘(1 + 𝑎) + h + hp ⋅ length) ⋅ 𝑛]
	// ht := sig[(1 + k * (1 + a)) * n..(1 + k * (1 + a) + h + hp * length) * n]			

	// compute message digest, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := pk.ctx.hmsg(sig.r, pk.seed, pk.root, msg, m)!

	// first (k.a)/8 bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎)/8]
	mut tmp_idxtree := []u8{len: 12}
	mut tmp_idxleaf := []u8{len: 4}

	// first (𝑘⋅𝑎 ⌉ 8 ) bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ (𝑘⋅𝑎 ⌉ 8 )] [0 ∶ ⌈𝑘⋅𝑎8 ⌉ bytes 8 ⌉]
	md := digest[0..ka8]

	// splitting digest into idxTree and idxLeaf
	mut start := ka8
	mut innerstart := 12 - hhd
	mut stop := ka8 + hhd

	copy(mut tmp_idxtree[innerstart..], digest[start..stop])
	start += hhd
	stop = start + h8d
	innerstart = 4 - h8d
	copy(mut tmp_idxleaf[innerstart..], digest[start..stop])

	mut idxtree := make_treeindex(tmp_idxtree, hhd).mod_2b(h - hp)
	idxleaf := u32(to_int(tmp_idxleaf, 4)) & ((1 << hp) - 1)

	// compute FORS public key
	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟ee)
	// ADRS.setTypeAndClear(FORS_TREE)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_tree_address(idxtree)
	addr.set_type_and_clear(.fors_tree)
	addr.set_keypair_address(idxleaf)

	// PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pkfors := fors_pkfromsig(pk.ctx, sig.fors, md, pk.seed, mut addr)!

	// return ht_verify(pk.ctx, pkfors, ht, pk.seed, idxtree, idxleaf, pk.root)!
	return ht_verify(pk.ctx, pkfors, sig.ht, pk.seed, mut idxtree, idxleaf, pk.root)!
}

const max_context_string_size = 255
// 10.2.1 Pure SLH-DSA Signature Generation
//
// Algorithm 22 slh_sign(𝑀, 𝑐𝑡𝑥, SK)
// Generates a pure SLH-DSA signature.
// Input: Message 𝑀, context string cs, private key SK.
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn slh_sign(msg []u8, cs []u8, sk &SecretKey, opt SignerOpts) !&SLHSignature {
	// Check context string size, should not exceed max_context_string_size
	if cs.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// randomized random for the randomized variant or
	// 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛, substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	opt_rand := if opt.deterministic {
		sk.pk.seed
	} else {
		// TODO: handle with crypto.rand
		rand.read(sk.ctx.prm.n)!
	}

	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msgout := []u8{cap: 1 + 1 + cs.len + msg.len}
	// to_byte(0, 1)(0, 1)
	msgout << u8(0)
	// to_byte(|𝑐𝑡𝑥|, 1), |𝑐𝑡𝑥| should fit in 1-byte
	msgout << u8(cs.len)
	msgout << cs
	msgout << msg

	// SIG ← slh_sign_internal(msg []u8, sk &SecretKey, addrnd []u8) !&SLHSignature
	// ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(msgout, sk, opt_rand)!

	return sig
}

// 10.2.2 HashSLH-DSA Signature Generation
//
// Algorithm 23 hash_slh_sign(𝑀, 𝑐𝑡𝑥, PH, SK)
// Generates a pre-hash SLH-DSA signature.
// Input: Message 𝑀, context string cs, pre-hash function PH, private key SK.
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn hash_slh_sign(msg []u8, cs []u8, ph crypto.Hash, sk &SecretKey, opt SignerOpts) !&SLHSignature {
	if cs.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// randomized random for the randomized variant or
	// substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	addrnd := if opt.deterministic {
		sk.pk.seed
	} else {
		rrbytes := rand.read(sk.ctx.prm.n)!
		rrbytes
	}
	// the biggest 64-bytes
	mut phm := []u8{cap: 64}
	mut oid := []u8{cap: 11}

	match ph {
		.sha256 {
			// OID ← toByte(0x0609608648016503040201, 11)
			oid = [u8(0x06), 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
			// PH𝑀 ← SHA-256(𝑀)
			phm = sha256.sum256(msg)
		}
		.sha512 {
			// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
			oid = [u8(0x06), 0x09, u8(0x60), u8(0x86), u8(0x48), u8(0x01), u8(0x65), u8(0x03),
				u8(0x04), u8(0x02), u8(0x03)]
			// PH𝑀 ← SHA-512(𝑀)
			phm = sha512.sum512(msg)
		}
		// need to be patched into .shake128
		.sha3_224 {
			// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
			oid = [u8(0x06), 0x09, u8(0x60), u8(0x86), u8(0x48), u8(0x01), u8(0x65), u8(0x03),
				u8(0x04), u8(0x02), u8(0x0B)]
			// 17: PH𝑀 ← SHAKE128(𝑀, 256), 32-bytes
			phm = sha3.shake128(msg, 32)
		}
		// need to be patched into .shake256
		.sha3_256 {
			// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
			oid = [u8(0x06), (0x09), u8(0x60), u8(0x86), u8(0x48), u8(0x01), u8(0x65), u8(0x03),
				u8(0x04), u8(0x02), u8(0x0C)]
			// PH𝑀 ← SHAKE256(𝑀, 512), 64-bytes
			phm = sha3.shake256(msg, 64)
		}
		else {
			return error('Unsupported hash')
		}
	}

	// 𝑀′ ← toByte(1, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PHm
	mut msgout := []u8{cap: 1 + 1 + cs.len + oid.len + phm.len}
	msgout << u8(0x01) // to_byte(0, 1)(1, 1)
	msgout << u8(cs.len) // to_byte(|𝑐𝑡𝑥|, 1), |𝑐𝑡𝑥| should fit in 1-byte
	msgout << cs
	msgout << oid
	msgout << phm

	// SIG ← slh_sign_internal(𝑀′, SK, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(msgout, sk, addrnd)!

	return sig
}

// 10.3 SLH-DSA Signature Verification
//
// Algorithm 24 slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PK)
// Verifies a pure SLH-DSA signature.
// Input: Message 𝑀, signature sig , context string 𝑐𝑡𝑥, public key PK.
// Output: Boolean.
@[direct_array_access; inline]
fn slh_verify(msg []u8, sig &SLHSignature, cs []u8, pk &PubKey, opt SignerOpts) !bool {
	if cs.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msgout := []u8{cap: 1 + 1 + cs.len + msg.len}
	msgout << u8(0)
	msgout << u8(cs.len)
	msgout << cs
	msgout << msg

	// return slh_verify_internal(msg []u8, sig &SLHSignature, pk &PubKey) !bool
	return slh_verify_internal(msgout, sig, pk)!
}

/*
// Algorithm 25 hash_slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PH, PK)
// Verifies a pre-hash SLH-DSA signature.
// Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK.
// Output: Boolean.
@[inline]
fn hash_slh_verify(c &Context, m []u8, sig []u8, cx []u8, ph crypto.Hash, p &PubKey) !bool {
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// default to sha256
	// OID ← toByte(0x0609608648016503040201, 11)
	mut oid := to_byte(0, 1)(u64(0x0609608648016503040201), 11)
	// PH𝑀 ← SHA-256(𝑀 )
	mut phm := sha256.sum256(m)

	match ph {
		.sha256 {
			// do nothing
		}
		.sha512 {
			// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
			oid = to_byte(0, 1)(u64(0x0609608648016503040203), 11)
			// PH𝑀 ← SHA-512(𝑀 )
			phm = sha512.sum512(m)
		}
		// need to be patched into .shake128
		.sha3_224 {
			// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
			oid = to_byte(0, 1)(u64(0x060960864801650304020B), 11)
			// 17: PH𝑀 ← SHAKE128(𝑀, 256)
			phm = sha3.shake128(m, 256)
		}
		// // need to be patched into .shake256
		.sha3_256 {
			// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
			oid = to_byte(0, 1)(u64(0x060960864801650304020C), 11)
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
