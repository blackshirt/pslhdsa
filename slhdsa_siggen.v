// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature generation module
module pslhdsa

import crypto
import crypto.rand

// 10.2.1 Pure SLH-DSA Signature Generation
//
// Algorithm 22 slh_sign(𝑀, 𝑐𝑡𝑥, SK)
// Generates a pure SLH-DSA signature with crypto.rand for randomness.
// Input: Message 𝑀, context string cx, private key SK.
// Output: SLH-DSA signature bytes SIG.
// slh_sign generates a pure SLH-DSA signature with crypto.rand for randomness.
@[direct_array_access]
pub fn slh_sign(msg []u8, cx []u8, sk &SigningKey) ![]u8 {
	// Check context string size, should not exceed max_context_string_size
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// randomized random for the randomized variant or
	// 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛, substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	opt_rand := rand.read(sk.ctx.prm.n)!

	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	msgout := encode_msg_purehash(cx, msg)

	// SIG ← slh_sign_internal(msg []u8, sk &SigningKey, addrnd []u8) !&SLHSignature
	// ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sigrandom := slh_sign_internal(msgout, sk, opt_rand)!

	return sigrandom.bytes()
}

// 9.2 SLH-DSA Signature Generation
//
// Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
// Generates an SLH-DSA signature.
// Input: Message 𝑀, private key SK = (SK.seed, SK.prf, PK.seed, PK.root),
// (optional) additional random 𝑎𝑑𝑑𝑟𝑛𝑑
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn slh_sign_internal(msg []u8, sk &SigningKey, addrnd []u8) !&SLHSignature {
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
	// opt_rand := unsafe { addrnd }

	// generate randomizer, 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
	r := sk.ctx.prf_msg(sk.prf, addrnd, msg, outlen)!
	// SIG ← r

	// compute message digest, ie, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := sk.ctx.hmsg(r, sk.pkseed, sk.pkroot, msg, msize)!

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

	mut idxtree := make_treeindex(tmp_idxtree, hhd).mod_2b(h - hp)
	idxleaf := u32(to_int(tmp_idxleaf, 4)) & ((1 << hp) - 1)

	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(idxtree)
	// ADRS.setTypeAndClear(FORS_TREE)
	addr.set_type_and_clear(.fors_tree)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_keypair_address(idxleaf)

	// SIG𝐹𝑂𝑅𝑆 ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	fors := fors_sign(sk.ctx, md, sk.seed, sk.pkseed, mut addr)!
	// SIG ← SIG ∥ SIG𝐹𝑂𝑅s

	// get FORS key, PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pkfors := fors_pkfromsig(sk.ctx, fors, md, sk.pkseed, mut addr)!
	// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹𝑂𝑅𝑆, SK.seed, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	ht := ht_sign(sk.ctx, pkfors, sk.seed, sk.pkseed, mut idxtree, idxleaf)!

	// : SIG ← SIG ∥ SIG𝐻𝑇

	// : return SIG
	sig := &SLHSignature{
		r:    r
		fors: fors
		ht:   ht
	}
	return sig
}

// HashSLH-DSA Signature Generation
//
// Algorithm 22 hash_slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
// Generates a pre-hash SLH-DSA signature.
// Input: Message 𝑀, private key SK = (SK.seed, SK.prf, PK.seed, PK.root),
// (optional) additional random 𝑎𝑑𝑑𝑟𝑛𝑑
// Output: SLH-DSA signature SIG.

// 10.2.2 HashSLH-DSA Signature Generation
//
// Algorithm 23 hash_slh_sign(𝑀, 𝑐𝑡𝑥, PH, SK)
// Generates a pre-hash SLH-DSA signature.
// Input: Message 𝑀, context string cx, pre-hash function PH, private key SK.
// Output: SLH-DSA signature SIG.
@[direct_array_access]
pub fn hash_slh_sign(msg []u8, cx []u8, ph crypto.Hash, sk &SigningKey) ![]u8 {
	// check for context string
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// TODO: add supported hash algorithms into list
	if ph !in supported_prehash_algo {
		return error('hash must be one of the supported prehash algorithms')
	}
	// substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	opt_rand := rand.read(sk.ctx.prm.n)!

	// pre-hashed message encoding
	//
	// get the ASN.1 DER serialized bytes for the hash oid
	oid := oid_for_hashfunc(ph)!
	// pre-hashed message with ph
	phm := phm_for_hashfunc(ph, msg)!

	// pre-hash message encoding
	msgout := encode_msg_prehash(cx, oid, phm)

	// SIG ← slh_sign_internal(𝑀′, SK, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(msgout, sk, opt_rand)!

	return sig.bytes()
}
