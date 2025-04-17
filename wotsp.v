module pslhdsa

// WOTS+ chaining function
//
// Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//
// Chaining function used in WOTS+.
// Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.
// Output: Value of F iterated 𝑠 times on 𝑋.
// (where 𝑖 + 𝑠 < w
fn chain(c Context, x []u8, i int, s int, pk_seed []u8, addr_ Address) ![]u8 {
	assert x.len == c.n
	if i + s >= w {
		return error('Invalid wots+ params')
	}
	mut addr := addr_.clone()
	mut tmp := x.clone()
	for j := i; j < i + s; j++ {
		// ADRS.setHashAddress(𝑗)
		addr.set_hash_address(u32(j))
		// 𝑡𝑚𝑝 ← F(PK.seed, ADRS,𝑡𝑚𝑝)
		tmp = c.f(pk_seed, addr, tmp)!
	}
	return tmp
}

// 5.1 WOTS+ Public-Key Generation
// Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)
// Generates a WOTS+ public key.
// Input: Secret seed SK.seed, public seed PK.seed, address ADRS.
// Output: WOTS+ public key 𝑝k
fn wots_pkgen(c Context, sk_seed []u8, pk_seed []u8, addr_ Address) ![]u8 {
	assert addr_.get_type()! == .wots_hash
	// copy address to create key generation key address
	mut addr := addr_.clone()
	mut sk_addr := addr.clone()
	// skADRS.setTypeAndClear(WOTS_PRF)
	sk_addr.set_type_and_clear(.wots_prf)
	// skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	sk_addr.set_keypair_address(addr.get_keypair_address())

	// gets wotsp length from the current context
	wots_len := c.wots_len()
	// temporary buffer to store output
	mut tmp := []u8{}
	for i := 0; i < wots_len; i++ {
		// skADRS.setChainAddress(𝑖)
		sk_addr.set_chain_address(u32(i))
		// compute secret value for chain i, 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)
		skey := c.prf(pk_seed, sk_seed, sk_addr)!
		// ADRS.setChainAddress(𝑖)
		addr.set_chain_address(u32(i))
		// compute public value for chain 𝑖, 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑘, 0, 𝑤 − 1, PK.seed, ADRS)
		tmp_i := chain(c, skey, 0, w - 1, pk_seed, addr)!
		tmp << tmp_i
	}
	// copy address to create WOTS+public key address, wotspkADRS ← ADRS
	mut wots_pk_addr := addr.clone()
	// wotspkADRS.setTypeAndClear(WOTS_PK)
	wots_pk_addr.set_type_and_clear(.wots_pk)
	// wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	// TODO: remove int cast
	wots_pk_addr.set_keypair_address(addr.get_keypair_address())
	// compress public key, 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS,𝑡𝑚𝑝)
	pk := c.tlen(c.wots_len(), pk_seed, wots_pk_addr, tmp)!

	return pk
}

// 5.2 WOTS+ Signature Generation
// A WOTS+ signature is an array of 𝑙𝑒𝑛 byte strings of length n
//
// Algorithm 7 wots_sign(𝑀, SK.seed, PK.seed, ADRS)
// Generates a WOTS+ signature on an 𝑛-byte message.
// Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS.
// Output: WOTS+ signature 𝑠𝑖𝑔.
fn wots_sign(c Context, m []u8, sk_seed []u8, pk_seed []u8, addr_ Address) ![]u8 {
	mut csum := u64(0)
	mut addr := addr_.clone()
	// convert message to base w, ie, 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1)
	len1 := c.len1()
	mut msgs := base_2exp_b(m, c.lgw, len1)

	// compute checksum
	for i := 0; i < len1; i++ {
		// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
		csum += w - 1 - msgs[i]
	}
	// for 𝑙𝑔𝑤 = 4, left shift by 4, its only values supported in this module
	// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)
	csum <<= 4 // u64((8 - ((len2 * c.lgw) % 8)) % 8)

	// convert to base w, 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2*𝑙𝑔𝑤)/8⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2)
	// mlen := 2 // cdiv(len2 * c.lgw, 8)
	// dump(mlen)
	// bytes := to_bytes(csum, mlen)
	msgs << base_2exp_b(to_bytes(csum, 2), c.lgw, len2)

	// copy address to create key generation key address
	mut sk_addr := addr.clone()
	// skADRS.setTypeAndClear(WOTS_PRF)
	sk_addr.set_type_and_clear(.wots_prf)
	// skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	// TODO: handle int > larger than max_int
	sk_addr.set_keypair_address(u32(addr.get_keypair_address()))

	mut sig := []u8{}
	for i := 0; i < c.wots_len(); i++ {
		// skADRS.setChainAddress(𝑖)
		sk_addr.set_chain_address(u32(i))
		// compute chain 𝑖 secret value, 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)
		skey := c.prf(pk_seed, sk_seed, sk_addr)!
		addr.set_chain_address(u32(i))
		// compute chain 𝑖 signature value, 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)
		sig_i := chain(c, skey, 0, int(msgs[i]), pk_seed, addr)!
		sig << sig_i
	}
	return sig
}

// 5.3 Computing a WOTS+ Public Key From a Signature
//
// Algorithm 8 wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
// Computes a WOTS+ public key from a message and its signature.
// Input: WOTS+ signature 𝑠𝑖𝑔, message 𝑀, public seed
// Output: WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔.
fn wots_pkfromsig(c Context, sig []u8, m []u8, pk_seed []u8, addr_ Address) ![]u8 {
	mut csum := u64(0)
	mut addr := addr_.clone()
	// convert message to base w, ie, 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1)
	len1 := c.len1()
	mut msgs := base_2exp_b(m, c.lgw, len1)

	// compute checksum
	// for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do
	for i := 0; i < len1; i++ {
		// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
		csum += (w - 1 - msgs[i])
	}
	// for 𝑙𝑔𝑤 = 4, left shift by 4, its only values supported in this module
	// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8)
	csum <<= 4 // u64((8 - ((len2 * c.lgw) % 8)) % 8)

	// convert to base w, 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2*𝑙𝑔𝑤)/8⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2)
	// mlen := 2 // cdiv(len2 * c.lgw, 8)
	// bytes := to_bytes(csum, mlen)
	msgs << base_2exp_b(to_bytes(csum, 2), c.lgw, len2)

	mut tmp := []u8{}
	for i := 0; i < c.wots_len(); i++ {
		// ADRS.setChainAddress(𝑖)
		addr.set_chain_address(u32(i))
		// 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑖𝑔[𝑖], 𝑚𝑠𝑔[𝑖], 𝑤 − 1 − 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)
		x := sig[i * c.n..(i + 1) * c.n]
		next_chain := chain(c, x, int(msgs[i]), int(w - 1 - msgs[i]), pk_seed, addr)!
		assert next_chain.len != 0

		tmp << next_chain
	}
	// copy address to create WOTS+ public key address, wotspkADRS ← ADRS
	mut wots_pk_addr := addr.clone()
	// wotspkADRS.setTypeAndClear(WOTS_PK)
	wots_pk_addr.set_type_and_clear(.wots_pk)
	// wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	// TODO: remove int casts ??
	wots_pk_addr.set_keypair_address(addr.get_keypair_address())
	// 𝑝𝑘𝑠𝑖𝑔 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS,𝑡𝑚𝑝)
	pk_sig := c.tlen(c.wots_len(), pk_seed, wots_pk_addr, tmp)!

	return pk_sig
}

fn wots_csum(c Context, m []u8) u64 {
	mut csum := u64(0)
	t := u32((1 << c.lgw) - 1)

	len1 := c.len1()
	mut msg := base_2exp_b(m, c.lgw, len1)

	// for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do
	for i := 0; i < len1; i++ {
		// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
		csum += t - msg[i]
	}

	csum <<= u64((8 - ((len2 * c.lgw) & 7)) & 7)

	return csum
}
