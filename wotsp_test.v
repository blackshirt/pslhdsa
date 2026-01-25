// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Test file for WOTS+
module pslhdsa

import arrays
import encoding.hex

// Test 1
struct WotsPKGenTest {
	skseed      string
	pkseed      string
	expected_pk string
}

// The test material was adapted from the Golang version of go-slh-dsa
fn test_wots_pkgen() {
	tests := [
		WotsPKGenTest{'00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', 'eacc640342e9455da67b7498b9dbc180'},
		WotsPKGenTest{'ffffffffffffffffffffffffffffffff', '00000000000000000000000000000000', 'b0d697cb87b1225a06cf3d6a07e91d20'},
	]
	ctx := new_context(.shake_128f)
	mut adrs := Address{}
	for i, item in tests {
		skseed := hex.decode(item.skseed)!
		pkseed := hex.decode(item.pkseed)!
		expected_pk := hex.decode(item.expected_pk)!
		// wots_pkgen(c &Context, skseed []u8, pkseed []u8, mut adr Address)
		actual_pk := wots_pkgen(ctx, skseed, pkseed, mut adrs)!
		assert actual_pk == expected_pk
	}
}

// Test 2
//
struct WotsSignVerifyTest {
	skseed       string
	pkseed       string
	message      string
	expected_sig string
}

fn test_wotsp_sign_verify() ! {
	tests := [
		WotsSignVerifyTest{'00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', '1d8cff94837952216aca752fad2bae148bd351bf7f72e44ebf88a54ba30621392af92b1d6ac4d8a7425c2685ea6c47c1eb7077ef9817fff78dded68815f36dfb9fb132d18bd833ccfd093d6bc79c9c9a7b0b1af2b88be036734af0b2d4a64ac216e64cb68f0fa075e12b08f1370d5b2a5fd923e2ac43d78eeb82430cea93ae398802b955817e67dea5119b9e27b7eb30c863a644371fa98c275220b16958a671cd362216622b840c2821fe0000f99670d6579c2a604d85d5a4db21bb10784c6359dbc5bc3ef3511e90b46c5bec9c8045e52d6dd25c7b04f0231288db99ce04adacaa3cb1a61523d3ac147a6563169f822409ff673401710ee8250c073a0656e0a35ec35c6dd953e52141fc704dee97d3bd04e9855d04bc37d792bb8b1e60093c802c2a08722d9f9f90e5eda00448c7fa82141adba465b955fd971183dd008d26ec4efb8235ddff418832e073effcb50502d7862df634c05aa74ca40e854e4bb5060de58d0e479b941dba4452eba052f88846494e2a6a1cc1046ae2e26e9bc36a438fee4f15a285d09bb7f17080a9e62ab6dc4d6120f014bda703779f957de6f46675c1f11920cfbd0a9b2b817d84181a78f59d3d78d6b78598c11667edc5e667762d092a1a6ebd24b1b34fd37c7487fe879e2e0a1e66ee99d9e3644432824649a0cc4cf668b30232dc02167e6d74e0cb5800178438bfdde4238a05a44f9031551efac16d2824eca3294ad3e5468612993d58cad4a272b401de6764dbd06f09bb80b62585d5e1944fba4919bf697a0f92'},
		WotsSignVerifyTest{'ffffffffffffffffffffffffffffffff', '00000000000000000000000000000000', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'bdb07bb7c73d3641b3add3843dd34b6ee2f740ffb715414b308aad09c7dfbe01c4c98fc7deef92ce0827b0df3ae490c8454b6eaef357a1016e09cb8112d9e221f6b5cb271fb9060629653c0057233edd059d0b9035697aa4e2abc08c5c3001529d2cf39965d7ccffde2b174059659ee2c025ffe931e4842753f47db60ab6f377c072ae6f6859bf39f1408623609ee848b15cbb6ddb66a3576770f23ec7793e140361166a848cb3acde88aa22968db631229ac7e807c641e6241c121da0373abe5dc6116d71632b2f82ac238eeab0c4c3162ce502a62dbd7c0147e81523af3376cce3890a075918a2d8996ca7cc5cf8a3f5d0793b3e47f7395abfba7552dcbf66697127ba45b9ee9cc0d652d719d615ac699aef2127dbc0cd464590120f4e1d01db5bb640dd8a7f63e1d700342d103a3e54d84abc28ba43a082818ff0623acc05d0299c37b6bacfe1f613f94d596abbce4342ec2c5be0802bd556e9718503a1cfb8f4f602757852369dcdc00cc3394f09b4e23d9a371f63c16d0e7f8dd84d970dfdd2d27163259c9d6b9464a13abb5ee73ef1e1e17959d566f1d98121774318bfa40b8c035ab7a0aa2f6136a5c99236e479cb9fcc1cfe2335ea1cc322dfdacad2446770d211856ba293b78cd707aaad890f53dda6c1ffcfab64eedc4ab1746afc6a74fa0f45e9a9600dcf703ec974804c24a677baeaf7772c704e755c48223f7c942a9d677cf56fc6fb9017743a87aaafdca15eb1d78114ff8c2329dd67d6ac0e3d7bf5ffff45910a1fa4831522d18a79'},
	]
	ctx := new_context(.shake_128f)
	mut adrs := Address{}
	for i, item in tests {
		skseed := hex.decode(item.skseed)!
		pkseed := hex.decode(item.pkseed)!
		message := hex.decode(item.message)!
		expected_sig := hex.decode(item.expected_sig)!
		// wots_sign(c &Context, m []u8, skseed []u8, pkseed []u8, mut adr Address) ![][]u8
		actual_sig := wots_sign(ctx, message, skseed, pkseed, mut adrs)!
		// flattened actual_sig
		flatten_sig := arrays.flatten[u8](actual_sig)
		assert flatten_sig == expected_sig

		public_key := wots_pkgen(ctx, skseed, pkseed, mut adrs)!
		// wots_pkfromsig(c &Context, sig []u8, m []u8, pkseed []u8, mut adr Address)
		recovered_pk := wots_pkfromsig(ctx, actual_sig, message, pkseed, mut adrs)!
		assert public_key == recovered_pk
	}
}
