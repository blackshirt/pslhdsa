module pslhdsa

import crypto.internal.subtle

// 7. The SLH-DSA Hypertree

// 7.1 Hypertree Signature Generation
//
// Algorithm 12 ht_sign(𝑀, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
// Generates a hypertree signature.
// Input: Message 𝑀, private seed SK.seed, public seed PK.seed, tree index 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, leaf index 𝑖𝑑𝑥𝑙𝑒𝑎𝑓.
// Output: HT signature SIG𝐻𝑇.
fn ht_sign(c Context, m []u8, sk_seed []u8, pk_seed []u8, idxtree_ int, idxleaf_ int) ![]u8 {
	mut idxtree := idxtree_
	mut idxleaf := idxleaf_

	// ADRS ← toByte(0, 32)
	mut addr := to_byte(0, 32)
	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(u64(idxtree))
	// SIG𝑡𝑚𝑝 ← xmss_sign(𝑀, SK.seed,𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.seed, ADRS)
	mut sig_tmp := xmms_sign(c, m, sk_seed, idxleaf, pk_seed, mut addr)!
	// SIG𝐻𝑇 ← SIG𝑡𝑚p
	mut sig_ht := sig_tmp.clone()
	// 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀, PK.seed, ADRS)
	mut root := xmms_pkfromsig(c, idxleaf, sig_tmp, m, pk_seed, mut addr)!

	// for 𝑗 from 1 to 𝑑 − 1
	for j := 1; j <= c.prm.d - 1; j++ {
		// 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′, ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒e
		idx_leaf = idx_tree % (1 << c.prm.hp)
		// remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒e, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′
		idx_tree = idx_tree >> c.prm.hp
		// ADRS.setLayerAddress(𝑗)
		addr.set_layer_address(u32(j))
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		addr.set_tree_address(u32(idxtree))
		// SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡, SK.seed,𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.seed, ADRS)
		sig_tmp = xmms_sign(c, root, sk_seed, idxleaf, pk_seed, mut addr)!
		// SIG𝐻𝑇 ← SIG𝐻𝑇 ∥ SIG𝑡𝑚p
		sig_ht << sig_tmp
		if j < c.prm.d - 1 {
			// 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑟𝑜𝑜𝑡, PK.seed, ADRS)
			root = xmms_pkfromsig(c, idxleaf, sig_tmp, root, pk_seed, mut addr)!
		}
	}
	return sig_ht
}

// 7.2 Hypertree Signature Verification
//
// Algorithm 13 ht_verify(𝑀, SIG𝐻𝑇, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.root)
// Verifies a hypertree signature.
// Input: Message 𝑀,signature SIG𝐻𝑇, public seed PK.seed, tree index 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, leaf index 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, HT public key P
fn ht_verify(c Context, m []u8, sig_ht []u8, pk_seed []u8, idxtree_ int, idx_leaf int, pk_root []u8) !bool {
	mut idxtree := idxtree_
	mut idxleaf := idxleaf_

	// ADRS ← toByte(0, 32)
	mut addr := to_byte(0, 32)
	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(u32(idxtree))
	// SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(0) ▷ SIG𝐻𝑇[0 ∶ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
	mut sig_tmp := sig_ht[..(c.prm.hp + c.prm.wots_len()) * c.prm.n]
	// 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀, PK.seed, ADRS)
	mut node := xmms_pkfromsig(c, idxleaf, sig_tmp, m, pk_seed, mut addr)!

	for j := 1; j <= c.prm.d - 1; j++ {
		// 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′, ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒e
		idx_leaf = idx_tree % (1 << c.prm.hp)
		// remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒e, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′
		idx_tree = idx_tree >> c.prm.hp
		// ADRS.setLayerAddress(𝑗)
		addr.set_layer_address(u32(j))
		// 10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
		addr.set_tree_address(u32(idxtree))

		// SIG𝑡𝑚𝑝 ← SIG𝐻𝑇.getXMSSSignature(𝑗) ▷ SIG𝐻𝑇[𝑗 ⋅ (ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛 ∶ (𝑗 + 1)(ℎ′ + 𝑙𝑒𝑛) ⋅ 𝑛]
		start := j * (c.prm.hp + c.prm.wots_len()) * c.prm.n
		end := (j + 1) * (c.prm.hp + c.prm.wots_len() * c.prm.n)
		sig_tmp = sig_ht[start..end]

		// 𝑛𝑜𝑑𝑒 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑛𝑜𝑑𝑒, PK.seed, ADRS)
		node = xmms_pkfromsig(c, idxleaf, sig_tmp, node, pk_seed, mut addr)!
	}

	// if 𝑛𝑜𝑑𝑒 = PK.root { return true }
	return subtle.constant_time_compare(node, pk_root) == 1
}
