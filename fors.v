module pslhdsa

// 8. Forest of Random Subsets (FORS)

// 8.1 Generating FORS Secret Values
//
// Algorithm 14 fors_skGen(SK.seed, PK.seed, ADRS, 𝑖𝑑𝑥)
// Generates a FORS private-key value.
// Input: Secret seed SK.seed, public seed PK.seed, address ADRS, secret key index 𝑖𝑑𝑥.
// Output: 𝑛-byte FORS private-key value.
fn fors_skgen(c Context, sk_seed []u8, pk_seed []u8, addr Address, idx int) ![]u8 {
	// idx >=0
	// copy address to create key generation address
	mut sk_addr := addr.clone()
	// skADRS.setTypeAndClear(FORS_PRF)
	sk_addr.set_type_and_clear(.fors_prf)
	// 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	sk_addr.set_keypair_address(addr.get_keypair_address())
	// skADRS.setTreeIndex(𝑖𝑑𝑥)
	sk_addr.set_tree_index(u32(idx))

	// return PRF(PK.seed, SK.seed,skADRS)
	return c.prf(pk_seed, sk_seed, sk_addr)
}

// 8.2 Generating a Merkle Hash Tree
//
// Algorithm 15 fors_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
// Computes the root of a Merkle subtree of FORS public values.
// Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed, address ADRS.
// Output: 𝑛-byte root 𝑛𝑜𝑑𝑒.
fn fors_node(c Context, sk_seed []u8, i int, z int, pk_seed []u8, addr_ Address) ![]u8 {
	// if z > ctx.a or i >= ctx.k * 2**(ctx.a - z):
	if z > c.a || i >= c.k * (1 << (c.a - z)) {
		return error('Bad fors_node params')
		// return empty bytes instead ?
		// return []u8{}
	}
	mut addr := addr_.clone()
	if z == 0 {
		// 𝑠𝑘 ← fors_skGen(SK.seed, PK.seed, ADRS,𝑖)
		skey := fors_skgen(c, sk_seed, pk_seed, addr, i)!
		// 3: ADRS.setTreeHeight(0)
		addr.set_tree_height(u32(0))
		// 4: ADRS.setTreeIndex(𝑖)
		addr.set_tree_index(u32(i))
		// 5: 𝑛𝑜𝑑𝑒 ← F(PK.seed, ADRS, 𝑠𝑘)
		node := c.f(pk_seed, addr, skey)!
		return node
	}
	// else
	// 𝑙𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
	lnode := fors_node(c, sk_seed, 2 * i, z - 1, pk_seed, addr)!
	// 8: 𝑟𝑛𝑜𝑑𝑒 ← fors_node(SK.seed, 2𝑖 + 1, 𝑧 − 1, PK.seed, ADRS)
	rnode := fors_node(c, sk_seed, 2 * i + 1, z - 1, pk_seed, addr)!
	// 9: ADRS.setTreeHeight(𝑧)
	addr.set_tree_height(u32(z))
	// 10: ADRS.setTreeIndex(𝑖)
	addr.set_tree_index(u32(i))
	// 11: 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
	mut m2 := []u8{}
	m2 << lnode
	m2 << rnode
	node := c.h(pk_seed, addr, m2)!

	return node
}

// 8.3 Generating a FORS Signature
//
// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
// Generates a FORS signature.
// Input: Message digest 𝑚𝑑, secret seed SK.seed, address ADRS, public seed PK.seed.
// Output: FORS signature SIG𝐹𝑂𝑅𝑆.
fn fors_sign(c Context, md []u8, sk_seed []u8, pk_seed []u8, addr_ Address) ![]u8 {
	assert md.len == cdiv(c.k * c.a, 8)
	mut addr := addr_.clone()
	// initialize SIG𝐹𝑂𝑅𝑆 as a zero-length byte string
	mut sig_fors := []u8{}
	//  𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)
	indices := base_2exp_b(md, c.a, c.k)

	// compute signature elements
	for i := 0; i < c.k; i++ {
		// fors_skGen(SK.seed, PK.seed, ADRS,𝑖 ⋅ 2^𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		fors_item := fors_skgen(c, sk_seed, pk_seed, addr, i << c.a + int(indices[i]))!
		sig_fors << fors_item

		// compute auth path
		mut auth := []u8{}
		// for 𝑗 from 0 to 𝑎 − 1 do
		for j := 0; j < c.a; j++ {
			// s ← ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2^𝑗⌋ ⊕ 1
			s := (indices[i] >> j) ^ 1
			// AUTH[𝑗] ← fors_node(SK.seed,𝑖 * 2^(𝑎−𝑗) + 𝑠, 𝑗, PK.seed, ADRS)
			idx := u32(i) << (c.a - j) + s
			auth_j := fors_node(c, sk_seed, int(idx), j, pk_seed, addr)!
			auth << auth_j
		}
		// SIG𝐹𝑂𝑅𝑆 ← SIG𝐹𝑂𝑅𝑆 ∥ AUTH
		sig_fors << auth
	}
	return sig_fors
}

// 8.4 Computing a FORS Public Key From a Signature
//
// Algorithm 17 fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
// Computes a FORS public key from a FORS signature.
// Input: FORS signature SIG𝐹𝑂𝑅𝑆, message digest 𝑚𝑑, public seed PK.seed, address ADRS.
// Output: FORS public key
fn fors_pkfromsig(c Context, sig_fors []u8, md []u8, pk_seed []u8, addr_ Address) ![]u8 {
	// assert sig_fors.len == c.k * (c.a + 1) * c.n
	assert md.len == cdiv(c.k * c.a, 8)
	mut addr := addr_.clone()
	// 𝑖𝑛𝑑𝑖𝑐𝑒𝑠 ← base_2b(𝑚𝑑, 𝑎, 𝑘)
	indices := base_2exp_b(md, c.a, c.k)
	mut node := [][]u8{len: 2}
	mut root := []u8{}
	for i := 0; i < c.k; i++ {
		// 𝑠𝑘 ← SIG𝐹𝑂𝑅𝑆.getSK(𝑖), SIG𝐹𝑂𝑅𝑆[𝑖 ⋅ (𝑎 + 1) ⋅ 𝑛 ∶ (𝑖 ⋅ (𝑎 + 1) + 1) ⋅ 𝑛]
		start := i * (c.a + 1) * c.n
		end := (i * (c.a + 1) + 1) * c.n
		skey := sig_fors[start..end]
		// compute leaf
		// ADRS.setTreeHeight(0)
		addr.set_tree_height(0)
		// ADRS.setTreeIndex(𝑖 ⋅ 2^𝑎 + 𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖])
		tree_idx := u32(i) << c.a + indices[i]
		addr.set_tree_index(tree_idx)
		// 𝑛𝑜𝑑𝑒[0] ← F(PK.seed, ADRS, 𝑠𝑘)
		node[0] = c.f(pk_seed, addr, skey)!

		// compute root from leaf and AUTH
		// 𝑎𝑢𝑡ℎ ← SIG𝐹𝑂𝑅𝑆.getAUTH(𝑖) ▷ SIG𝐹𝑂𝑅𝑆[(𝑖 ⋅ (𝑎 + 1) + 1) ⋅ 𝑛 ∶ (𝑖 + 1) ⋅ (𝑎 + 1) ⋅ 𝑛]
		auth_start := (i * (c.a + 1) + 1) * c.n
		auth_end := (i + 1) * (c.a + 1) * c.n
		auth := sig_fors[auth_start..auth_end]
		for j := 0; j < c.a; j++ {
			// ADRS.setTreeHeight(𝑗 + 1)
			addr.set_tree_height(u32(j + 1))
			// if ⌊𝑖𝑛𝑑𝑖𝑐𝑒𝑠[𝑖]/2^𝑗⌋ is even
			if (indices[i] >> j) & 1 == 0 {
				// ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
				addr.set_tree_index(addr.get_tree_index() >> 1)
				// 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑛𝑜𝑑𝑒[0] ∥ 𝑎𝑢𝑡ℎ[𝑗])
				mut msi := []u8{}
				auth_j := auth[j * c.n..(j + 1) * c.n]
				// auth[j * c.n..(j + 1) * c.n]
				msi << node[0]
				msi << auth_j
				node[1] = c.h(pk_seed, addr, msi)!
			} else {
				// ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
				addr.set_tree_index((addr.get_tree_index() - 1) >> 1)
				// 15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑎𝑢𝑡ℎ[𝑗] ∥ 𝑛𝑜𝑑𝑒[0])
				mut msi := []u8{}
				// msi << auth[j * c.n..(j + 1) * c.n]
				auth_j := auth[j * c.n..(j + 1) * c.n]
				msi << auth_j
				msi << node[0]
				node[1] = c.h(pk_seed, addr, msi)!
			}
			// 𝑛𝑜𝑑𝑒[0] ← 𝑛𝑜𝑑𝑒[1]
			node[0] = unsafe { node[1] }
		}
		// 𝑟𝑜𝑜𝑡[𝑖] ← 𝑛𝑜𝑑𝑒[0]
		root << node[0]
	}
	// copy address to create a FORS public-key address, 	forspkADRS ← ADRS ▷
	mut fors_pkaddr := addr.clone()
	// 22: forspkADRS.setTypeAndClear(FORS_ROOTS)
	fors_pkaddr.set_type_and_clear(.fors_roots)
	// 23: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	fors_pkaddr.set_keypair_address(u32(addr.get_keypair_address()))

	// compute the FORS public key
	// 24: 𝑝𝑘 ← T𝑘(PK.seed, forspkADRS, 𝑟𝑜𝑜𝑡) ▷
	pk := c.tlen(pk_seed, fors_pkaddr, root)!

	return pk
}
