// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Test file for XMSS signature scheme
// The test material was adapted from the golang version of slh_dsa module
module pslhdsa

import encoding.hex

// Test 1
struct XmmsNodeTest {
	skseed   string
	pkseed   string
	expected string
}

fn test_xmms_node() ! {
	tests := [
		XmmsNodeTest{'01010101010101010101010101010101', '02020202020202020202020202020202', '94e24679fb2460b97332db131c38bec9'},
		XmmsNodeTest{'00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', '730d37bd3958c074e91f6d44be88fe99'},
	]
	c := new_context(.shake_128f)
	for item in tests {
		skseed := hex.decode(item.skseed)!
		pkseed := hex.decode(item.pkseed)!
		expected := hex.decode(item.expected)!
		mut addr := new_address()
		// xmss_node(c &Context, sk_seed []u8, i u32, z u32, pk_seed []u8, mut addr Address) ![]u8
		node := xmss_node(c, skseed, 0, 3, pkseed, mut addr)!
		assert expected == node
	}
}

// Test 2
struct XmmsSignTest {
	m            string
	skseed       string
	pkseed       string
	idx          u32
	expected_sig string
	expected_pk  string
}

fn test_xmms_sign() ! {
	tests := [
		XmmsSignTest{'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', '00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', 0x72A1B175, 'bfdd679d61d4148164f479ecf053a1a63c72ee27256419a749b1c8ab44c1879091bbeb53fa28e5479706e387c20b6c9e83711efc9e38280cef52de7c817d6a908e51586b9fb8a4def536c1b75b6bc1bc05ff3bccf4ecc93a53b7a925f1e75801471b87330baa937e5201a2557add3e6370a95ce57179e828cd7330580f4e3649cea7107c57b033bae1f9cf8f40ce8f7da000864a61911683430e8c2b494cfca7dfa23861432c644f968c790cff937fdc9ba9abca2997aef67b3214d64c353f859e186ca16fa88e51025fba49234817d77cb03dec976e12326f1a9a49c10c4a0dc235e7e926faade7ea79767a48c1d03da76acbd3125256389e8771c80ed5b17404a92a93652686cb27aed39aef36edead54efa312ef596613fcef71c49720e3ce031d6e5b86cbc112ffa8559dbafd415ab908032e0057f4474667ea847d1d191417319b3e02f40840234340ee93d26b4433e8638fba22bbe6c2132d90b4536d33cd6b17f8c7b14e036febca5ed996891ee4c34e136d888f823a1ce9e6d6414af48d844d465557bc483d15aa832cc07ec8a8c7d99a6180c7e03662dc0508530cfa759a727665167b65013ec337646917e1e7180ca5a49aedd10793e6980032a7b8083f78b34d9f294db5adf80d94fd551b602f5bf1df0aedeaa3528387641d91da3bdb66c28c2babf0039cc33ee4f096d663620425d05f64c9a26efc72b64abb31e4df0bcef2eab5e69b6fca3850a6d7d99986e41b8ec46647bcf7fbafc09803b1c47601565d6c7b8d7dd84effcede05882241bef37b03f1ca29877cb7579e5ca5c2c2024288aeb4edcff320dcaa959dbc028a5a10e3d6a8017ed2a12a9f5cdc0', 'abcf26c2b039145f2b3349ec2156289f'},
		XmmsSignTest{'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'ffffffffffffffffffffffffffffffff', '00000000000000000000000000000000', 0x72A1B175, 'b71dbcfef097ab66d898524572455d577ad6a0210240009242e8876a65724044d4cc9ac2c84b24ae08baf3bf26fa0b85f77586a187fa4556c5bf252def71b9ae3f60f74109e5afc9c8ed4b3a24f1dfa1c9a0046bba1529d43cbaca27f6a8b51f29cb56e8114755f51b4484d19429996e49d819487ab9e11aa29d74788edd4fd180f60ba15c03a6afded2a0ad75a2920e0dba461f3e2988f5a9f05979fb0cffb18af727d1e3acf4a5699822f7814be709283a7a18ed69d90ca451a1869ee4a197f5a863b2ee3310def9392b38278974a90b166ced6f602fd1ce285decc84cbd14815e50302919b91f5ce0398f13e4a4e7497e776cd630e132c49281080433bc685f570e9845cbf3229a9e01b1fdeffca48fe9bb759966be11b695278bbc8dc7cb72a8046392d70fc1dfc19d55f765b8283a20f4107510ae36772657ce17439213d41b6f68e342898be416be4755e156060fcafa6c2d1d8346721419ec73835c1bf564baa3b6960e4cae213871b2f5db1f921e9378426a8da7c36916b5aaac200830013c3b3aae58b8ad0b8966b87db1e898d1c8d030b7068f8576778d0e47bffe834c8029ff85a4e665d5ac8a88ac0f37b425f6332ad667e12d6e0ec7ed206c2122a6bc57aa282c51dcc42759f380a1b704cd1c25130b332c2a7cfbe494fa539dbc5d8cbe92b6c9967742040fad5027213374d421310c1b0c82599937ee6a49083efe06e41710561486d7fcff92f9dc9afc7c1928688caf6471ac7508f8e3f35ab8f86c907d23845854435cd8a874e921734f50485e2b46878a5223bf7e2be3f832e6c272f9c33a9b12e2ed4fa0446ac08976460de67a8b19cb453ed59826a0d0', '69bfa62dd4d4cba6a40398e16511ecb1'},
	]
	c := new_context(.shake_128f)
	for item in tests {
		m := hex.decode(item.m)!
		skseed := hex.decode(item.skseed)!
		pkseed := hex.decode(item.pkseed)!
		expected_sig := hex.decode(item.expected_sig)!
		expected_pk := hex.decode(item.expected_pk)!
		mut addr := new_address()
		// xmss_sign(c &Context, m []u8, skseed []u8, idx int, pkseed []u8, mut addr Address) !&XmssSignature
		xmss_sig := xmss_sign(c, m, skseed, item.idx, pkseed, mut addr)!

		assert expected_sig == xmss_sig.bytes()

		// xmms_pkfromsig(c &Context, idx u32, sig_xmss &XmssSignature, m []u8, pkseed []u8, mut addr Address) ![]u8
		pk_from_sig := xmms_pkfromsig(c, item.idx, xmss_sig, m, pkseed, mut addr)!
		assert expected_pk == pk_from_sig

		// test for parsing xmss signature
		out_xmss := parse_xmss_signature(c, expected_sig)!
		assert out_xmss.wots_sign == xmss_sig.wots_sign
		assert out_xmss.auth_path == xmss_sig.auth_path
	}
}
