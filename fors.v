// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Forest of Random Subsets (FORS) module
module pslhdsa

// 8. Forest of Random Subsets (FORS)

// 8.1 Generating FORS Secret Values
//
// Algorithm 14 fors_skGen(SK.seed, PK.seed, ADRS, 𝑖𝑑𝑥)
// Generates a FORS private-key value.
// Input: Secret seed SK.seed, public seed PK.seed, address ADRS, secret key index 𝑖𝑑𝑥.
// Output: 𝑛-byte FORS private-key value.
@[direct_array_access; inline]
fn fors_skgen(c &Context, skseed []u8, pkseed []u8, addr Address, idx u32) ![]u8 {
	// idx >=0
	// copy address to create key generation address
	mut skaddr := addr.clone()
	// skADRS.setTypeAndClear(FORS_PRF)
	skaddr.set_type_and_clear(.fors_prf)
	// 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	skaddr.set_keypair_address(addr.get_keypair_address())
	// skADRS.setTreeIndex(𝑖𝑑𝑥)
	skaddr.set_tree_index(idx)

	// return PRF(PK.seed, SK.seed,skADRS)
	return c.prf(pkseed, skseed, skaddr, c.prm.n)!
}

// 8.2 Generating a Merkle Hash Tree
//
// Algorithm 15 fors_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
// Computes the root of a Merkle subtree of FORS public values.
// Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed, address ADRS.
// Output: 𝑛-byte root 𝑛𝑜𝑑𝑒.
@[direct_array_access; inline]
fn fors_node(c &Context, skseed []u8, i u32, z u32, pkseed []u8, mut addr Address) ![]u8 {
	if z == 0 {
		// 𝑠𝑘 ← fors_skGen(SK.seed, PK.seed, ADRS,𝑖)
		skey := fors_skgen(c, skseed, pkseed, addr, i)!
		// 3: ADRS.setTreeHeight(0)
		addr.set_tree_height(0)
		// 4: ADRS.setTreeIndex(𝑖)
		addr.set_tree_index(i)

		// 5: 𝑛𝑜𝑑𝑒 ← F(PK.seed, ADRS, 𝑠𝑘)
		// the outlen was c.prm.n
		node := c.f(pkseed, addr, skey, c.prm.n)!
		return node
	}
	// Otherwise,
	//
	// 𝑙𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
	lnode := fors_node(c, skseed, 2 * i, z - 1, pkseed, mut addr)!
	// 8: 𝑟𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖 + 1, 𝑧 − 1, PK.seed, ADRS)
	rnode := fors_node(c, skseed, 2 * i + 1, z - 1, pkseed, mut addr)!
	// 9: ADRS.setTreeHeight(𝑧)
	addr.set_tree_height(z)
	// 10: ADRS.setTreeIndex(𝑖)
	addr.set_tree_index(i)

	// 11: 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
	mut m2 := []u8{cap: lnode.len + rnode.len}
	m2 << lnode
	m2 << rnode
	node := c.h(pkseed, addr, m2, c.prm.n)!

	return node
}

// 8.3 Generating a FORS Signature
//
// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
// Generates a FORS signature.
// Input: Message digest 𝑚𝑑, secret seed SK.seed, address ADRS, public seed PK.seed.
// Output: FORS signature SIG𝐹𝑂𝑅𝑆.
@[direct_array_access; inline]
fn fors_sign(c &Context, md []u8, skseed []u8, pkseed []u8, mut addr Address) ![]u8 {
	assert md.len == cdiv(c.prm.k * c.prm.a, 8)
	// initialize SIG𝐹𝑂𝑅𝑆 as a zero-length byte string
	mut sig_fors := []u8{}
	//  𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)
	indices := base_2b(md, c.prm.a, c.prm.k)

	// compute signature elements
	for i := u32(0); i < c.prm.k; i++ {
		// fors_skGen(SK.seed, PK.seed, ADRS,𝑖 ⋅ 2^𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		fors_item := fors_skgen(c, skseed, pkseed, addr, i << c.prm.a + indices[i])!
		sig_fors << fors_item

		// compute auth path
		mut auth := []u8{}
		// for 𝑗 from 0 to 𝑎 − 1 do
		for j := u32(0); j < c.prm.a; j++ {
			// s ← ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2^𝑗⌋ ⊕ 1
			s := (indices[i] >> j) ^ 1
			// AUTH[𝑗] ← fors_node(SK.seed,𝑖 * 2^(𝑎−𝑗) + 𝑠, 𝑗, PK.seed, ADRS)
			idx := i << (u32(c.prm.a) - j) + s
			auth_j := fors_node(c, skseed, idx, j, pkseed, mut addr)!
			auth << auth_j
		}
		// SIG𝐹𝑂𝑅𝑆 ← SIG𝐹𝑂𝑅𝑆 ∥ AUTH
		sig_fors << auth
	}
	return sig_fors
}

/*
// 8.4 Computing a FORS Public Key From a Signature
//
// Algorithm 17 fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
// Computes a FORS public key from a FORS signature.
// Input: FORS signature SIG𝐹𝑂𝑅𝑆, message digest 𝑚𝑑, public seed PK.seed, address ADRS.
// Output: FORS public key
fn fors_pkfromsig(c &Context, sig_fors []u8, md []u8, pkseed []u8, addr_ Address) ![]u8 {
	// assert sig_fors.len == c.prm.k * (c.prm.a + 1) * c.n
	assert md.len == cdiv(c.prm.k * c.prm.a, 8)
	mut addr := addr_.clone()
	// 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)
	indices := base_2b(md, c.prm.a, c.prm.k)
	mut node_0 := []u8{}
	mut node_1 := []u8{}
	mut root := []u8{}
	for i := 0; i < c.prm.k; i++ {
		// 𝑠𝑘 ← SIG𝐹𝑂𝑅𝑆.getSK(𝑖), SIG𝐹𝑂𝑅𝑆[𝑖 ⋅ (𝑎 + 1) ⋅ 𝑛 ∶ (𝑖 ⋅ (𝑎 + 1) + 1) ⋅ 𝑛]
		start := i * (c.prm.a + 1) * c.n
		end := (i * (c.prm.a + 1) + 1) * c.n
		skey := sig_fors[start..end]
		// compute leaf
		// ADRS.setTreeHeight(0)
		addr.set_tree_height(0)
		// ADRS.setTreeIndex(𝑖 ⋅ 2^𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		tree_idx := u32(i) << c.prm.a + indices[i]
		addr.set_tree_index(tree_idx)
		// 𝑛𝑜𝑑𝑒[0] ← F(PK.seed, ADRS, 𝑠𝑘)
		node_0 = c.f(pkseed, addr, skey)!

		// compute root from leaf and AUTH
		// 𝑎𝑢𝑡ℎ ← SIG𝐹𝑂𝑅𝑆.getAUTH(𝑖) ▷ SIG𝐹𝑂𝑅𝑆[(𝑖 ⋅ (𝑎 + 1) + 1) ⋅ 𝑛 ∶ (𝑖 + 1) ⋅ (𝑎 + 1) ⋅ 𝑛]
		auth_start := (i * (c.prm.a + 1) + 1) * c.n
		auth_end := (i + 1) * (c.prm.a + 1) * c.n
		auth := sig_fors[auth_start..auth_end]
		for j := 0; j < c.prm.a; j++ {
			// ADRS.setTreeHeight(𝑗 + 1)
			addr.set_tree_height(u32(j + 1))
			// if ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2^𝑗⌋ is even
			if (indices[i] >> j) % 2 == 0 {
				// ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
				addr.set_tree_index(addr.get_tree_index() >> 1)
				// 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑛𝑜𝑑𝑒[0] ∥ 𝑎𝑢𝑡ℎ[𝑗])
				mut msi := []u8{}
				auth_j := auth[j * c.n..(j + 1) * c.n]
				msi << node_0
				msi << auth_j
				node_1 = c.h(pkseed, addr, msi)!
			} else {
				// ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
				addr.set_tree_index((addr.get_tree_index() - 1) >> 1)
				// 15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑎𝑢𝑡ℎ[𝑗] ∥ 𝑛𝑜𝑑𝑒[0])
				mut msi := []u8{}
				auth_j := auth[j * c.n..(j + 1) * c.n]
				msi << auth_j
				msi << node_0
				node_1 = c.h(pkseed, addr, msi)!
			}
			// 𝑛𝑜𝑑𝑒[0] ← 𝑛𝑜𝑑𝑒[1]
			node_0 = unsafe { node_1 }
		}
		// 𝑟𝑜𝑜𝑡[𝑖] ← 𝑛𝑜𝑑𝑒[0]
		root << node_0
	}
	// copy address to create a FORS public-key address, 	forspkADRS ← ADRS ▷
	mut fors_pkaddr := addr.clone()
	// 22: forspkADRS.setTypeAndClear(FORS_ROOTS)
	fors_pkaddr.set_type_and_clear(.fors_roots)
	// 23: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	fors_pkaddr.set_keypair_address(u32(addr.get_keypair_address()))

	// compute the FORS public key
	// 24: 𝑝𝑘 ← T𝑘(PK.seed, forspkADRS, 𝑟𝑜𝑜𝑡) ▷
	pk := c.tlen(pkseed, fors_pkaddr, root)!

	return pk
}
*/
