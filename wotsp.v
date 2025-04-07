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
		return error('Invalid params')
	}
	tmp := x.clone()
	for j := i; j < i + s; j++ {
		addr.set_hash_address(j)
		tmp = hash_fn(pk.seed, addr, tmp)
	}
	return tmp
}
