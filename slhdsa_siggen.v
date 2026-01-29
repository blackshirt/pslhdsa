// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA Signature generation module
module pslhdsa

import crypto
import crypto.rand
import crypto.sha3
import crypto.sha256
import crypto.sha512

const max_context_string_size = 255
// 10.2.1 Pure SLH-DSA Signature Generation
//
// Algorithm 22 slh_sign(𝑀, 𝑐𝑡𝑥, SK)
// Generates a pure SLH-DSA signature.
// Input: Message 𝑀, context string cx, private key SK.
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn slh_sign_random(msg []u8, cx []u8, sk &SigningKey) !&SLHSignature {
	// Check context string size, should not exceed max_context_string_size
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// randomized random for the randomized variant or
	// 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛, substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	opt_rand := rand.bytes(sk.ctx.prm.n)!

	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	msgout := compose_msg(u8(0), cx, msg)

	// SIG ← slh_sign_internal(msg []u8, sk &SigningKey, addrnd []u8) !&SLHSignature
	// ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(msgout, sk, opt_rand)!

	return sig
}

// slh_sign_deterministic generates a deterministic SLH-DSA signature.
@[direct_array_access; inline]
fn slh_sign_deterministic(msg []u8, cx []u8, sk &SigningKey) !&SLHSignature {
	// use the public key seed as the random seed for deterministic signature generation
	msgout := compose_msg(u8(0), cx, msg)
	return slh_sign_internal(msgout, sk, sk.pkseed)!
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
	mut opt_rand := addrnd.clone()

	// generate randomizer, 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
	r := sk.ctx.prf_msg(sk.prf, opt_rand, msg, outlen)!
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

	idxtree := make_treeindex(tmp_idxtree, hhd).mod_2b(h - hp)
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
	mut idxtree_c := idxtree.clone()
	ht := ht_sign(sk.ctx, pkfors, sk.seed, sk.pkseed, mut idxtree_c, idxleaf)!

	// : SIG ← SIG ∥ SIG𝐻𝑇

	// : return SIG
	sig := &SLHSignature{
		r:    r
		fors: fors
		ht:   ht
	}
	return sig
}

// 10.2.2 HashSLH-DSA Signature Generation
//
// Algorithm 23 hash_slh_sign(𝑀, 𝑐𝑡𝑥, PH, SK)
// Generates a pre-hash SLH-DSA signature.
// Input: Message 𝑀, context string cx, pre-hash function PH, private key SK.
// Output: SLH-DSA signature SIG.
@[direct_array_access; inline]
fn hash_slh_sign(msg []u8, cx []u8, ph crypto.Hash, sk &SigningKey, opt SignerOpts) !&SLHSignature {
	if cx.len > max_context_string_size {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// randomized random for the randomized variant or
	// substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant,
	addrnd := if opt.deterministic {
		sk.pkseed
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
	mut msgout := []u8{cap: 1 + 1 + cx.len + oid.len + phm.len}
	msgout << u8(0x01) // to_byte(0, 1)(1, 1)
	msgout << u8(cx.len) // to_byte(|𝑐𝑡𝑥|, 1), |𝑐𝑡𝑥| should fit in 1-byte
	msgout << cx
	msgout << oid
	msgout << phm

	// SIG ← slh_sign_internal(𝑀′, SK, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(msgout, sk, addrnd)!

	return sig
}

// Helpers for message combination

// compose_msg combines the message components into a single message.
@[direct_array_access; inline]
fn compose_msg(me u8, cx []u8, msg []u8) []u8 {
	// 𝑀′ ← toByte(me, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msgout := []u8{cap: 2 + cx.len + msg.len}
	// to_byte(me, 1)
	msgout << me
	// to_byte(|𝑐𝑡𝑥|, 1), |𝑐𝑡𝑥| should fit in 1-byte
	if cx.len == 0 {
		msgout << cx
	} else {
		msgout << u8(cx.len)
		msgout << cx
	}
	msgout << msg

	return msgout
}
