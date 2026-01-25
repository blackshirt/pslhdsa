// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// eXtended Merkle Signature Scheme (XMSS) module
module pslhdsa

import arrays

// XMSS Signature
//
// An XMSS signature is (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛 bytes in length and consists of a WOTS+ signature
// and an xmss authentication path.
@[noinit]
struct XmssSignature {
mut:
	// wots+ signatures
	wots_sign [][]u8
	// authentication path
	auth_path [][]u8
}

// no check is performed
@[inline]
fn new_xmss_signature(wots [][]u8, auth [][]u8) &XmssSignature {
	return &XmssSignature{
		wots_sign: wots
		auth_path: auth
	}
}

// parse_xmss_signature parses bytes into XmssSignature
@[direct_array_access; inline]
fn parse_xmss_signature(c &Context, bytes []u8) !&XmssSignature {
	length := c.wots_len()
	// the size of xmss signatures is (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛
	calc := (c.prm.hp + length) * c.prm.n
	if bytes.len != calc {
		return error('incorrect length for XmssSignature')
	}
	// start with wots+ signature
	mut start := 0
	mut wots_sign := [][]u8{len: length}
	for i := 0; i < length; i++ {
		end := start + c.prm.n
		chunk := bytes[start..end]
		wots_sign[i] = []u8{len: c.prm.n}
		copy(mut wots_sign[i], chunk)
		start += c.prm.n
	}

	// auth path
	mut auth := [][]u8{len: c.prm.hp}
	for i := 0; i < c.prm.hp; i++ {
		end := start + c.prm.n
		chunk := bytes[start..end]
		auth[i] = []u8{len: c.prm.n}
		copy(mut auth[i], chunk)
		start += c.prm.n
	}

	return &XmssSignature{
		wots_sign: wots_sign
		auth_path: auth
	}
}

// get_wots_sig  gets the copies of underlying WOTS+ signatures
@[inline]
fn (x &XmssSignature) get_wots_sig() [][]u8 {
	mut tmp := [][]u8{len: x.wots_sign.len}
	for i := 0; i < x.wots_sign.len; i++ {
		tmp[i] = []u8{len: x.wots_sign[i].len}
		copy(mut tmp[i], x.wots_sign[i])
	}
	return tmp
}

// get_xmss_auth gets the copies of underlying xmss authentication path
@[inline]
fn (x &XmssSignature) get_xmss_auth() [][]u8 {
	mut tmp := [][]u8{len: x.auth_path.len}
	for i := 0; i < x.auth_path.len; i++ {
		tmp[i] = []u8{len: x.auth_path[i].len}
		copy(mut tmp[i], x.auth_path[i])
	}
	return tmp
}

// xmss_size returns the total size of XmssSignature x, in bytes.
@[inline]
fn (x &XmssSignature) xmss_size() int {
	return x.wots_size() + x.auth_size()
}

// wots_size returns the length of wots signatures of XmssSignature x
@[inline]
fn (x &XmssSignature) wots_size() int {
	mut n := 0
	for v in x.wots_sign {
		n += v.len
	}
	return n
}

// auth_size returns the length of authentication path of XmssSignature x
@[inline]
fn (x &XmssSignature) auth_size() int {
	mut n := 0
	for v in x.auth_path {
		n += v.len
	}
	return n
}

// bytes returns flatten-ed XmssSignature x into bytes array
@[inline]
fn (x &XmssSignature) bytes() []u8 {
	flattened_wots := arrays.flatten[u8](x.wots_sign)
	flattened_auth := arrays.flatten[u8](x.auth_path)

	mut out := []u8{cap: x.xmss_size()}
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
	// the outlen param was 8*c.prm.n-bits, ie, c.prm.n bytes length
	return c.h(pkseed, addr, gab, c.prm.n)!
}

// 6.2 Generating an XMSS Signature
//
// Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
// Generates an XMSS signature.
// Input: 𝑛-byte message 𝑀, secret seed SK.seed, index 𝑖𝑑𝑥, public seed PK.seed,
// address ADRS.
// Output: XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH).
fn xmss_sign(c &Context, m []u8, skseed []u8, idx u32, pkseed []u8, mut addr Address) !&XmssSignature {
	mut auth := [][]u8{len: c.prm.hp}
	// build authentication path
	for j := u32(0); j < c.prm.hp; j++ {
		// 𝑘 ← ⌊𝑖𝑑𝑥/2^𝑗⌋ ⊕ 1
		k := (idx >> j) ^ 1
		// 3: AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗, PK.seed, ADRS)
		auth[j] = xmss_node(c, skseed, k, j, pkseed, mut addr)!
	}
	// ADRS.setTypeAndClear(WOTS_HASH)
	addr.set_type_and_clear(.wots_hash)
	// 6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	addr.set_keypair_address(idx)

	// 7: 𝑠𝑖𝑔 ← wots_sign(𝑀, SK.seed, PK.seed, ADRS)
	// wots signature was defined as [][]u8 arrays
	sig := wots_sign(c, m, skseed, pkseed, mut addr)!

	// 8: SIG𝑋𝑀𝑆𝑆 ← 𝑠𝑖𝑔 ∥ AUTH
	return &XmssSignature{
		wots_sign: sig
		auth_path: auth
	}
}

// 6.3 Computing an XMSS Public Key From a Signature
//
// Algorithm 11 xmss_pkFromSig(𝑖𝑑𝑥, SIG𝑋𝑀𝑆𝑆, 𝑀, PK.seed, ADRS)
// Computes an XMSS public key from an XMSS signature.
// Input: Index 𝑖𝑑𝑥, XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH), 𝑛-byte message, public seed PK.seed, address ADRS.
// Output: 𝑛-byte root value 𝑛𝑜𝑑𝑒[0].
@[direct_array_access; inline]
fn xmms_pkfromsig(c &Context, idx u32, sig_xmss &XmssSignature, m []u8, pkseed []u8, mut addr Address) ![]u8 {
	// compute WOTS+ pk from WOTS+ 𝑠𝑖g, ADRS.setTypeAndClear(WOTS_HASH)
	addr.set_type_and_clear(.wots_hash)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	addr.set_keypair_address(idx)
	// SIG𝑋𝑀𝑆𝑆[0 ∶ 𝑙𝑒𝑛 ⋅ 𝑛], 𝑠𝑖𝑔 ← SIG𝑋𝑀𝑆𝑆.getWOTSSig()
	sig := sig_xmss.get_wots_sig() // sig_xmss[0..c.wots_len() * c.prm.n]
	// : AUTH ← SIG𝑋𝑀𝑆𝑆.getXMSSAUTH() ▷ SIG𝑋𝑀𝑆𝑆[𝑙𝑒𝑛 ⋅ 𝑛 ∶ (𝑙𝑒𝑛 + ℎ′) ⋅ 𝑛]
	auth := sig_xmss.get_xmss_auth() // sig_xmss[c.wots_len() * c.prm.n..(c.wots_len() + c.prm.hp) * c.prm.n]

	// 𝑛𝑜𝑑𝑒[0] ← wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
	// wots_pkfromsig(c &Context, sig [][]u8, m []u8, pkseed []u8, mut adr Address) ![]u8
	mut node_0 := wots_pkfromsig(c, sig, m, pkseed, mut addr)!
	mut node_1 := []u8{}

	// compute root from WOTS+ pk and AUTH
	// ADRS.setTypeAndClear(TREE)
	addr.set_type_and_clear(.tree)
	// ADRS.setTreeIndex(𝑖𝑑𝑥)
	addr.set_tree_index(idx)

	for k := u32(0); k < c.prm.hp; k++ {
		// ADRS.setTreeHeight(𝑘 + 1)
		addr.set_tree_height(k + 1)
		mut m2 := []u8{cap: node_0.len + auth[k].len}
		// if ⌊𝑖𝑑𝑥/2^𝑘⌋ is even then
		if (idx >> k) % 2 == 0 {
			// 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
			addr.set_tree_index(u32(addr.get_tree_index() >> 1))
			// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑛𝑜𝑑𝑒[0] ∥ AUTH[𝑘])
			// m_auth_k := auth[k * c.prm.n..(k + 1) * c.prm.n]
			m2 << node_0
			m2 << auth[k]
			node_1 = c.h(pkseed, addr, m2, c.prm.n)!
		} else {
			// ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
			// TODO: correctly handles > max_int
			ix := u32((addr.get_tree_index() - 1) >> 1)
			addr.set_tree_index(ix)
			// 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, AUTH[𝑘] ∥ 𝑛𝑜𝑑𝑒[0])
			// m_auth_k := auth[k * c.prm.n..(k + 1) * c.prm.n]
			m2 << auth[k]
			m2 << node_0
			node_1 = c.h(pkseed, addr, m2, c.prm.n)!
		}
		node_0 = unsafe { node_1 }
	}
	return node_0
}
