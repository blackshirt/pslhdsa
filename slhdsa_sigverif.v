// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature verification module
module pslhdsa

import crypto

// 10.3 SLH-DSA Signature Verification
//
// Algorithm 24 slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PK)
// Verifies a pure SLH-DSA signature.
// Input: Message 𝑀, signature sig , context string 𝑐𝑡𝑥, public key PK.
// Output: Boolean.
@[direct_array_access]
pub fn slh_verify(msg []u8, sig []u8, cx []u8, pk &PubKey) !bool {
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// parse signature bytes into SLHSignature struct
	parsed_sig := parse_slhsignature(pk.ctx, sig)!

	// return slh_verify_sig(msg []u8, sig &SLHSignature, cx []u8, pk &PubKey) !bool
	return slh_verify_sig(msg, parsed_sig, cx, pk)!
}

// pure SLH-DSA signature verification
// Input: Message 𝑀, SLHSignature sig , context string 𝑐𝑡𝑥, public key PK.
// Output: Boolean.
@[direct_array_access; inline]
fn slh_verify_sig(msg []u8, sig &SLHSignature, cx []u8, pk &PubKey) !bool {
	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	msgout := encode_msg_purehash(cx, msg)

	// return slh_verify_internal(msg []u8, sig &SLHSignature, pk &PubKey) !bool
	return slh_verify_internal(msgout, sig, pk)!
}

// 9.3 SLH-DSA Signature Verification
//
// Algorithm 20 slh_verify_internal(𝑀, SIG, PK)
// Verifies an SLH-DSA signature.
// Input: Message 𝑀, signature SIG, public key PK = (PK.seed, PK.root).
// Output: Boolean.
@[direct_array_access; inline]
fn slh_verify_internal(msg []u8, sig &SLHSignature, pk &PubKey) !bool {
	// localizes some context variables
	// n := pk.ctx.prm.n
	a := pk.ctx.prm.a
	k := pk.ctx.prm.k
	m := pk.ctx.prm.m
	h := pk.ctx.prm.h
	hp := pk.ctx.prm.hp

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
	// hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int)
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

	//
	// mut idxtree_cloned := idxtree.clone()
	// return ht_verify(pk.ctx, pkfors, ht, pk.seed, idxtree, idxleaf, pk.root)!
	return ht_verify(pk.ctx, pkfors, sig.ht, pk.seed, mut idxtree, idxleaf, pk.root)!
}

// Algorithm 25 hash_slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PH, PK)
// Verifies a pre-hash SLH-DSA signature.
// Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK.
// Output: Boolean.
@[direct_array_access]
pub fn hash_slh_verify(msg []u8, sig []u8, cx []u8, ph crypto.Hash, p &PubKey) !bool {
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// TODO: add supported hash algorithms into list
	if ph !in supported_prehash_algo {
		return error('hash must be one of the supported prehash algorithms')
	}
	// parse into SLHSignature opaque
	slh_sig := parse_slhsignature(p.ctx, sig)!

	// pre-hashed message encoding
	//
	// get the ASN.1 DER serialized bytes for the hash oid
	oid := oid_for_hashfunc(ph)!
	// pre-hashed message with ph
	phm := phm_for_hashfunc(ph, msg)!

	// pre-hash message encoding
	msgout := encode_msg_prehash(cx, oid, phm)

	// return slh_verify_internal(𝑀′, SIG, PK)
	return slh_verify_internal(msgout, slh_sig, p)!
}
