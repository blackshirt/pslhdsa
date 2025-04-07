module pslhdsa

// WOTS+ chaining function
//
// Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//
// Chaining function used in WOTS+.
// Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.
// Output: Value of F iterated 𝑠 times on 𝑋.
// (where 𝑖 + 𝑠 < w
fn chain(ctx Context, x []u8, i int, s int, pk_seed []u8, mut addr Adrs) ![]u8 {
	assert x.len == ctx.prm.n
	if i + s >= ctx.prm.w {
		return error('Invalid wots+ params')
	}
	mut tmp := x.clone()
	for j := i; j < i + s; j++ {
		addr.set_hash_address(j)
		tmp = ctx.f(pk.seed, addr, tmp)
	}
	return tmp
}

// 5.1 WOTS+ Public-Key Generation
// Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)
// Generates a WOTS+ public key.
// Input: Secret seed SK.seed, public seed PK.seed, address ADRS.
// Output: WOTS+ public key 𝑝k
fn wots_pkgen(ctx Context, sk_seed []u8, pk_seed []u8, mut addr Address) ![]u8 {
	// copy address to create key generation key address
	mut sk_addr := addr.clone()
	// skADRS.setTypeAndClear(WOTS_PRF)
	sk_addr.set_type_and_clear(.wots_prf)
	// skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	sk_addr.set_keypair_address(addr.get_keypair_address())

	// gets wotsp length from the current context
	wots_len := ctx.prm.wots_len()
	// temporary buffer to store output
	mut tmp := []u8{}
	for i := 0; i < wots_len - 1; i++ {
		// skADRS.setChainAddress(𝑖)
		sk_addr.set_chain_address(u32(i))
		// compute secret value for chain i, 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)
		sk := ctx.prf(pk_seed, sk_seed, sk_addr)
		// ADRS.setChainAddress(𝑖)
		addr.set_chain_address(u32(i))
		// compute public value for chain 𝑖, 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑘, 0, 𝑤 − 1, PK.seed, ADRS)
		tmp_i := chain(ctx, sk, 0, ctx.prm.w - 1, pk_seed, mut addr)!
		tmp << tmp_i
	}
	// copy address to create WOTS+public key address, wotspkADRS ← ADRS
	mut wots_pk_addr := addr.clone()
	// wotspkADRS.setTypeAndClear(WOTS_PK)
	wots_pk_addr.set_type_and_clear(.wots_pk)
	// wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	wots_pk_addr.set_keypair_address(addr.get_keypair_address())
	// compress public key, 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS,𝑡𝑚𝑝)
	pk := ctx.tlen(pk_seed, wots_pk_addr, tmp)

	return pk
}

// 5.2 WOTS+ Signature Generation
// A WOTS+ signature is an array of 𝑙𝑒𝑛 byte strings of length n
//
// Algorithm 7 wots_sign(𝑀, SK.seed, PK.seed, ADRS)
// Generates a WOTS+ signature on an 𝑛-byte message.
// Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS.
// Output: WOTS+ signature 𝑠𝑖𝑔.
fn wots_sign(ctx Context, m []u8, sk_seed []u8, pk_seed []u8, mut addr Address) ![]u8 {
	mut csum := 0
	// convert message to base w, ie, 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1)
	len1 := ctx.prm.len1()
	msgs := base_2exp_b(m, ctx.prm.lgw, len1)

	// compute checksum
	for i := 0; i < len1 - 1; i++ {
		// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
		csum += w - 1 - msgs[i]
	}
	// for 𝑙𝑔𝑤 = 4, left shift by 4, its only values supported in this module
	// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)
	csum <<= (8 - ((len2 * ctx.prm.lgw) % 8)) % 8

	// convert to base w, 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2*𝑙𝑔𝑤)/8⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2)
	mlen := cdiv(len2 * ctx.prm.lgw, 8)
	bytes := to_byte(u64(csum), mlen)
	msgs << base_2exp_b(bytes, ctx.prm.lgw, len2)

	// copy address to create key generation key address
	mut sk_addr := addr.clone()
	// skADRS.setTypeAndClear(WOTS_PRF)
	sk_addr.set_type_and_clear(.wots_prf)
	// skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	sk_addr.set_keypair_address(addr.get_keypair_address())

	mut sig := []u8{}
	for i := 0; i < ctx.prm.wots_Len(); i++ {
		// skADRS.setChainAddress(𝑖)
		sk_addr.set_chain_address(u32(i))
		// compute chain 𝑖 secret value, 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)
		sk := ctx.prf(pk_seed, sk_seed, mut sk_addr)
		addr.set_chain_address(u32(i))
		// compute chain 𝑖 signature value, 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)
		sig_i := chain(ctx, sk, 0, msg[i], pk_seed, mut addr)!
		sig << sig_i
	}
	return sig
}
