// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The SLH-DSA Hypertree module
module pslhdsa

import crypto.internal.subtle

// 7. The SLH-DSA Hypertree
//
// HypertreeSignature is hypertree signature, which is a tree of XMSS trees.
@[noinit]
struct HypertreeSignature {
mut:
	xmss []XmssSignature
}

// new_hypertree creates a new HypertreeSignature from a slice of XmssSignature
@[inline]
fn new_hypertree(xs []XmssSignature) &HypertreeSignature {
	return &HypertreeSignature{
		xmss: xs
	}
}

// ht_size returns the total size of HypertreeSignature h, in bytes.
//
// The size of a hypertree signature is (ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 bytes, where ℎ is the height of the hypertree,
// 𝑑 is the number of XMSS trees in the hypertree, 𝑙𝑒𝑛 is the length of each XMSS tree, and 𝑛 is the
// number of bytes in a signature of an XMSS tree.
@[inline]
fn (h &HypertreeSignature) ht_size() int {
	// for every item in xmss, add its size to n
	mut n := 0
	for x in h.xmss {
		n += x.xmss_size()
	}
	return n
}

// bytes returns flatten-ed HypertreeSignature h into bytes array
@[inline]
fn (h &HypertreeSignature) bytes() []u8 {
	mut out := []u8{len: h.ht_size()}
	mut n := 0
	for x in h.xmss {
		copy(mut out[n..n + x.xmss_size()], x.bytes())
		n += x.xmss_size()
	}
	return out
}

// A hypertree signature is (ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 bytes in length and consists of a sequence
// of 𝑑 XMSS signatures
@[direct_array_access]
fn parse_hypertree(c Context, sig []u8) !&HypertreeSignature {
	// single xmss signature size
	chunklen := (c.prm.hp + c.wots_len()) * c.prm.n
	if sig.len % chunklen != 0 {
		return error('invalid hypertree signature size')
	}
	mut start := 0
	mut xmss := []XmssSignature{len: c.prm.d}
	for i := 0; i < xmss.len; i++ {
		xmss[i] = parse_xmss_signature(c, sig[start..start + chunklen])!
		start += chunklen
	}
	return new_hypertree(xmss)
}

// 7.1 Hypertree Signature Generation
//
// Algorithm 12 ht_sign(𝑀, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
// Generates a hypertree signature.
// Input: Message 𝑀, private seed SK.seed, public seed PK.seed, tree index 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, leaf index 𝑖𝑑𝑥𝑙𝑒𝑎𝑓.
// Output: HT signature SIG𝐻𝑇.
// ht_sign generates a hypertree signature.
@[direct_array_access; inline]
fn ht_sign(c &Context, m []u8, skseed []u8, pkseed []u8, mut idxtree TreeIndex, idxleaf_ u32) !&HypertreeSignature {
	mut idxleaf := idxleaf_

	// ADRS ← toByte(0, 32)
	mut adrs := new_address()
	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	// NOTE: this does not handle idxtree > 2^64 - 1, where tree address is 12-bytes long
	adrs.set_tree_address(idxtree)
	// SIG𝑡𝑚𝑝 ← xmss_sign(𝑀, SK.seed,𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.seed, ADRS)
	// xmss_sign(c &Context, m []u8, skseed []u8, idx u32, pkseed []u8, mut addr Address) !&XmssSignature
	mut sigtmp := xmss_sign(c, m, skseed, idxleaf, pkseed, mut adrs)!
	// SIG𝐻𝑇 ← SIG𝑡𝑚p
	mut sight := []XmssSignature{len: c.prm.d}
	sight[0] = sigtmp.clone()
	// 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀, PK.seed, ADRS)
	mut root := xmms_pkfromsig(c, idxleaf, sigtmp, m, pkseed, mut adrs)!

	// for 𝑗 from 1 to 𝑑 − 1
	for j := u32(1); j < c.prm.d; j++ {
		// 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2^ℎ′, ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒e
		idxleaf = idxtree.residue(c.prm.hp)
		// remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒e, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′
		idxtree = idxtree.remove_bits(c.prm.hp)
		// ADRS.setLayerAddress(𝑗)
		adrs.set_layer_address(j)
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		adrs.set_tree_address(idxtree)
		// SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡, SK.seed,𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.seed, ADRS)
		sigtmp = xmss_sign(c, root, skseed, idxleaf, pkseed, mut adrs)!
		// SIG𝐻𝑇 ← SIG𝐻𝑇 ∥ SIG𝑡𝑚p
		sight[j] = sigtmp.clone()
		if j < c.prm.d - 1 {
			// 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑟𝑜𝑜𝑡, PK.seed, ADRS)
			root = xmms_pkfromsig(c, idxleaf, sigtmp, root, pkseed, mut adrs)!
		}
	}
	return new_hypertree(sight)
}

// 7.2 Hypertree Signature Verification
//
// Algorithm 13 ht_verify(𝑀, SIG𝐻𝑇, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.root)
// Verifies a hypertree signature.
// Input: Message 𝑀,signature SIG𝐻𝑇, public seed PK.seed, tree index 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, leaf index 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, HT public key PK.root.
// ht_verify verifies a hypertree signature.
@[direct_array_access; inline]
fn ht_verify(c &Context, m []u8, sight &HypertreeSignature, pkseed []u8, mut idxtree TreeIndex, idxleaf_ u32, pkroot []u8) !bool {
	// mut idxtree := idxtree
	mut idxleaf := idxleaf_

	// ADRS ← toByte(0, 32)
	mut adrs := new_address()
	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	// NOTE: this does not handle idxtree > 2^64 - 1, where tree address is 12-bytes long
	adrs.set_tree_address(idxtree)
	// SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(0) ▷ SIG𝐻𝑇[0 ∶ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
	// mut sigtmp := sight[0..(c.prm.hp + c.wots_len()) * c.prm.n].clone()
	mut sigtmp := sight.xmss[0]
	// 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀, PK.seed, ADRS)
	mut node := xmms_pkfromsig(c, idxleaf, sigtmp, m, pkseed, mut adrs)!

	// for 𝑗 from 1 to 𝑑 − 1 do
	for j := u32(1); j < c.prm.d; j++ {
		// 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2^ℎ′, ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒e
		idxleaf = idxtree.residue(c.prm.hp)
		// remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒e, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′
		idxtree = idxtree.remove_bits(c.prm.hp)
		// ADRS.setLayerAddress(𝑗)
		adrs.set_layer_address(j)
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		adrs.set_tree_address(idxtree)

		// SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(𝑗) ▷ SIG𝐻𝑇[𝑗 ⋅ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛 ∶ (𝑗 + 1)(ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
		sigtmp = sight.xmss[j]

		// 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑛𝑜𝑑𝑒, PK.seed, ADRS)
		node = xmms_pkfromsig(c, idxleaf, sigtmp, node, pkseed, mut adrs)!
	}

	// if 𝑛𝑜𝑑𝑒 = PK.root { return true }
	return subtle.constant_time_compare(node, pkroot) == 1
}
