// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// eXtended Merkle Signature Scheme (XMSS) module
module pslhdsa

import arrays

// XMSS Signature
//
@[noinit]
struct XmssSignature {
mut:
	wots_sig [][]u8
	auth     [][]u8
}

@[inline]
fn (x &XmssSignature) xmsssize() int {
	return x.wotssize() + x.authsize()
}

@[inline]
fn (x &XmssSignature) wotssize() int {
	mut n := 0
	for v in x.wots_sig {
		n += v.len
	}
	return n
}

@[inline]
fn (x &XmssSignature) authsize() int {
	mut n := 0
	for v in x.auth {
		n += v.len
	}
	return n
}

@[inline]
fn (x &XmssSignature) bytes() []u8 {
	flattened_wots := arrays.flatten[u8](x.wots_sig)
	flattened_auth := arrays.flatten[u8](x.auth)

	mut out := []u8{cap: x.xmsssize()}
	out << flattened_wots
	out << flattened_auth

	return out
}

// 6. eXtended Merkle Signature Scheme (XMSS)
// XMSS extends the WOTS+ signature scheme into one that can sign multiple messages.
// An XMSS signature is (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛 bytes in length and consists of a WOTS+ signature and an
// authentication path

// 6.1 Generating a Merkle Hash Tree
// Algorithm 9 xmss_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
// Computes the root of a Merkle subtree of WOTS+ public keys.
// Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed,
// address ADRS.
// Output: 𝑛-byte root 𝑛𝑜𝑑e
@[direct_array_access; inline]
fn xmss_node(c &Context, skseed []u8, i u32, z u32, pkseed []u8, mut addr Address) ![]u8 {
	assert skseed.len == c.prm.n
	assert pkseed.len == c.prm.n
	assert z <= c.prm.hp
	assert i < (1 << c.prm.hp - z)

	if z == 0 {
		// ADRS.setTypeAndClear(WOTS_HASH)
		addr.set_type_and_clear(.wots_hash)
		// ADRS.setKeyPairAddress(𝑖)
		addr.set_keypair_address(u32(i))
		// 𝑛𝑜𝑑𝑒 ← wots_pkGen(SK.seed, PK.seed, ADRS)
		// wots_pkgen(c &Context, skseed []u8, pkseed []u8, addr Address)
		return wots_pkgen(c, skseed, pkseed, mut addr)!
	}
	// otherwise
	// 𝑙𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
	lnode := xmss_node(c, skseed, 2 * i, z - 1, pkseed, mut addr)!
	// 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 − 1, PK.seed, ADRS)
	rnode := xmss_node(c, skseed, (2 * i) + 1, z - 1, pkseed, mut addr)!
	// 8: ADRS.setTypeAndClear(TREE)
	addr.set_type_and_clear(.tree)
	// 9: ADRS.setTreeHeight(𝑧)
	addr.set_tree_height(u32(z))
	// 10: ADRS.setTreeIndex(𝑖)
	addr.set_tree_index(u32(i))

	// 11: 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
	mut gab := []u8{cap: lnode.len + rnode.len}
	gab << lnode
	gab << rnode
	return c.h(pkseed, addr, gab, c.prm.n)!
}

/*
// 6.2 Generating an XMSS Signature
//
// Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
// Generates an XMSS signature.
// Input: 𝑛-byte message 𝑀, secret seed SK.seed, index 𝑖𝑑𝑥, public seed PK.seed,
// address ADRS.
// Output: XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH).
fn xmss_sign(c &Context, m []u8, skseed []u8, idx int, pkseed []u8, addr_ Address) ![]u8 {
	assert m.len == c.prm.n
	assert idx >= 0
	assert idx <= (1 << c.prm.hp)

	mut addr := addr_.clone()
	mut auth := []u8{}
	// build authentication path
	for j := 0; j < c.prm.hp; j++ {
		// 𝑘 ← ⌊𝑖𝑑𝑥/2^𝑗⌋ ⊕ 1
		k := (idx >> j) ^ 1
		// 3: AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗, PK.seed, ADRS)
		auth_j := xmss_node(c, skseed, k, j, pkseed, addr)!
		auth << auth_j
	}
	// ADRS.setTypeAndClear(WOTS_HASH)
	addr.set_type_and_clear(.wots_hash)
	// 6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	addr.set_keypair_address(u32(idx))
	// 7: 𝑠𝑖𝑔 ← wots_sign(𝑀, SK.seed, PK.seed, ADRS)
	sig := wots_sign(c, m, skseed, pkseed, mut addr)!
	// 8: SIG𝑋𝑀𝑆𝑆 ← 𝑠𝑖𝑔 ∥ AUTH
	mut sig_xmss := []u8{}
	sig_xmss << sig
	sig_xmss << auth

	assert sig_xmss.len == c.prm.n * (c.wots_len() + c.prm.hp)
	return sig_xmss
}

// 6.3 Computing an XMSS Public Key From a Signature
//
// Algorithm 11 xmss_pkFromSig(𝑖𝑑𝑥, SIG𝑋𝑀𝑆𝑆, 𝑀, PK.seed, ADRS)
// Computes an XMSS public key from an XMSS signature.
// Input: Index 𝑖𝑑𝑥, XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH), 𝑛-byte message, public seed PK.seed, address ADRS.
// Output: 𝑛-byte root value 𝑛𝑜𝑑𝑒[0].
fn xmms_pkfromsig(c &Context, idx int, sig_xmss []u8, m []u8, pkseed []u8, addr_ Address) ![]u8 {
	assert idx >= 0
	assert m.len == c.prm.n
	mut addr := addr_.clone()
	assert sig_xmss.len == (c.wots_len() + c.prm.hp) * c.prm.n
	// mut node := [][]u8{len: 2}
	// compute WOTS+ pk from WOTS+ 𝑠𝑖g, ADRS.setTypeAndClear(WOTS_HASH)
	addr.set_type_and_clear(.wots_hash)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	addr.set_keypair_address(u32(idx))
	// SIG𝑋𝑀𝑆𝑆[0 ∶ 𝑙𝑒𝑛 ⋅ 𝑛], 𝑠𝑖𝑔 ← SIG𝑋𝑀𝑆𝑆.getWOTSSig()
	sig := sig_xmss[0..c.wots_len() * c.prm.n]
	// : AUTH ← SIG𝑋𝑀𝑆𝑆.getXMSSAUTH() ▷ SIG𝑋𝑀𝑆𝑆[𝑙𝑒𝑛 ⋅ 𝑛 ∶ (𝑙𝑒𝑛 + ℎ′) ⋅ 𝑛]
	auth := sig_xmss[c.wots_len() * c.prm.n..(c.wots_len() + c.prm.hp) * c.prm.n]

	// 𝑛𝑜𝑑𝑒[0] ← wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
	mut node_0 := wots_pkfromsig(c, sig, m, pkseed, mut addr)!
	mut node_1 := []u8{}

	// compute root from WOTS+ pk and AUTH
	// ADRS.setTypeAndClear(TREE)
	addr.set_type_and_clear(.tree)
	// ADRS.setTreeIndex(𝑖𝑑𝑥)
	addr.set_tree_index(u32(idx))

	for k := 0; k < c.prm.hp; k++ {
		// ADRS.setTreeHeight(𝑘 + 1)
		addr.set_tree_height(u32(k + 1))
		// if ⌊𝑖𝑑𝑥/2^𝑘⌋ is even then
		if (idx >> k) % 2 == 0 {
			// 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
			addr.set_tree_index(u32(addr.get_tree_index() >> 1))
			// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑛𝑜𝑑𝑒[0] ∥ AUTH[𝑘])
			m_auth_k := auth[k * c.prm.n..(k + 1) * c.prm.n]
			mut m2 := []u8{}
			m2 << node_0
			m2 << m_auth_k
			node_1 = c.h(pkseed, addr, m2, c.prm.n)!
		} else {
			// ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
			// TODO: correctly handles > max_int
			ix := u32((addr.get_tree_index() - 1) >> 1)
			addr.set_tree_index(ix)
			// 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, AUTH[𝑘] ∥ 𝑛𝑜𝑑𝑒[0])
			m_auth_k := auth[k * c.prm.n..(k + 1) * c.prm.n]
			mut m2 := []u8{}
			m2 << m_auth_k
			m2 << node_0
			node_1 = c.h(pkseed, addr, m2, c.prm.n)!
		}
		node_0 = unsafe { node_1 }
	}
	return node_0
}
*/
