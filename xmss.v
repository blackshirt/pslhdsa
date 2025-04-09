module pslhdsa

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
fn xmss_node(c Context, sk_seed []u8, i int, z int, pk_seed []u8, mut addr Address) ![]u8 {
	if z > c.prm.hp || i >= (1 << (c.prm.hp - z)) {
		return error('bad xmss_node params')
	}
	if z == 0 {
		// ADRS.setTypeAndClear(WOTS_HASH)
		addr.set_type_and_clear(.wots_hash)
		// ADRS.setKeyPairAddress(𝑖)
		addr.set_keypair_address(u32(i))
		// 𝑛𝑜𝑑𝑒 ← wots_pkGen(SK.seed, PK.seed, ADRS)
		// wots_pkgen(c Context, sk_seed []u8, pk_seed []u8, mut addr Address)
		node := wots_pkgen(c, sk_seed, pk_seed, mut addr)!
		return node
	}
	// otherwise
	// 𝑙𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
	lnode := xmss_node(c, sk_seed, 2 * i, z - 1, pk_seed, mut addr)!
	// 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 − 1, PK.seed, ADRS)
	rnode := xmss_node(c, sk_seed, 2 * i + 1, z - 1, pk_seed, mut addr)!
	// 8: ADRS.setTypeAndClear(TREE)
	addr.set_type_and_clear(.tree)
	// 9: ADRS.setTreeHeight(𝑧)
	addr.set_tree_height(u32(z))
	// 10: ADRS.setTreeIndex(𝑖)
	addr.set_tree_index(u32(i))

	// 11: 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
	mut gab := []u8{}
	gab << lnode
	gab << rnode
	node := c.h(pk_seed, addr, gab)!

	return node
}

// 6.2 Generating an XMSS Signature
//
// Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
// Generates an XMSS signature.
// Input: 𝑛-byte message 𝑀, secret seed SK.seed, index 𝑖𝑑𝑥, public seed PK.seed,
// address ADRS.
// Output: XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH).
fn xmms_sign(c Context, m []u8, sk_seed []u8, idx int, pk_seed []u8, mut addr Address) ![]u8 {
	assert m.len == c.prm.n
	assert idx >= 0
	assert idx < (1 << c.prm.hp)

	mut auth := []u8{}
	// build authentication path
	for j := 0; j < c.prm.hp; j++ {
		// 𝑘 ← ⌊𝑖𝑑𝑥/2𝑗⌋ ⊕ 1
		k := (idx >> j) ^ 0x01
		// 3: AUTH[𝑗] ← xmss_node(SK.seed, 𝑘, 𝑗, PK.seed, ADRS)
		auth_j := xmss_node(c, sk_seed, k, j, pk_seed, mut addr)!
		auth << auth_j
	}
	// ADRS.setTypeAndClear(WOTS_HASH)
	addr.set_type_and_clear(.wots_hash)
	// 6: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	addr.set_keypair_address(u32(idx))
	// 7: 𝑠𝑖𝑔 ← wots_sign(𝑀, SK.seed, PK.seed, ADRS)
	sig := wots_sign(c, m, sk_seed, pk_seed, mut addr)!
	// 8: SIG𝑋𝑀𝑆𝑆 ← 𝑠𝑖𝑔 ∥ AUTH
	mut sig_xmss := []u8{}
	sig_xmss << sig
	sig_xmss << auth

	return sig_xmss
}

// 6.3 Computing an XMSS Public Key From a Signature
//
// Algorithm 11 xmss_pkFromSig(𝑖𝑑𝑥, SIG𝑋𝑀𝑆𝑆, 𝑀, PK.seed, ADRS)
// Computes an XMSS public key from an XMSS signature.
// Input: Index 𝑖𝑑𝑥, XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH), 𝑛-byte message, public seed PK.seed, address ADRS.
// Output: 𝑛-byte root value 𝑛𝑜𝑑𝑒[0].
fn xmms_pkfromsig(c Context, idx int, sig_xmss []u8, m []u8, pk_seed []u8, mut addr Address) ![]u8 {
	assert idx >= 0
	assert m.len == c.prm.n
	assert sig_xmss.len == (c.prm.wots_len() + c.prm.hp) * c.prm.n

	// compute WOTS+ pk from WOTS+ 𝑠𝑖g, ADRS.setTypeAndClear(WOTS_HASH)
	addr.set_type_and_clear(.wots_hash)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥)
	addr.set_keypair_address(u32(idx))
	// SIG𝑋𝑀𝑆𝑆[0 ∶ 𝑙𝑒𝑛 ⋅ 𝑛], 𝑠𝑖𝑔 ← SIG𝑋𝑀𝑆𝑆.getWOTSSig()
	sig := sig_xmss[..c.prm.wots_len() * c.prm.n]
	// : AUTH ← SIG𝑋𝑀𝑆𝑆.getXMSSAUTH() ▷ SIG𝑋𝑀𝑆𝑆[𝑙𝑒𝑛 ⋅ 𝑛 ∶ (𝑙𝑒𝑛 + ℎ′) ⋅ 𝑛]
	auth := sig_xmss[c.prm.wots_len() * c.prm.n..]

	// 𝑛𝑜𝑑𝑒[0] ← wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
	mut node_0 := wots_pkfromsig(c, sig, m, pk_seed, mut addr)!

	// compute root from WOTS+ pk and AUTH
	// ADRS.setTypeAndClear(TREE)
	addr.set_type_and_clear(.tree)
	// ADRS.setTreeIndex(𝑖𝑑𝑥)
	addr.set_tree_index(u32(idx))

	for k := 0; k <= c.prm.hp - 1; k++ {
		// ADRS.setTreeHeight(𝑘 + 1)
		addr.set_tree_height(u32(k + 1))
		if (idx >> k) % 2 == 0 {
			// 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
			addr.set_tree_index(u32(addr.get_tree_index() >> 1))
			// 12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑛𝑜𝑑𝑒[0] ∥ AUTH[𝑘])
			m_auth_k := auth[k * c.prm.n..(k + 1) * c.prm.n]
			mut m2 := []u8{}
			m2 << node_0
			m2 << m_auth_k
			node_1 := c.h(pk_seed, addr, m2)!
			node_0 = unsafe { node_1 }
		} else {
			// ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
			ix := (addr.get_tree_index() - 1) >> 1
			addr.set_tree_index(ix)
			// 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, AUTH[𝑘] ∥ 𝑛𝑜𝑑𝑒[0])
			m_auth_k := auth[k * c.prm.n..(k + 1) * c.prm.n]
			mut m2 := []u8{}
			m2 << m_auth_k
			m2 << node_0
			node_1 := c.h(pk_seed, addr, m2)!
			node_0 = unsafe { node_1 }
		}
	}
	return node_0
}
