// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Test file for fors functionality
// The test material was adapted from the golang version of slh_dsa module
module pslhdsa

import encoding.hex

struct ForsSKGenTest {
	skseed      string
	pkseed      string
	expected_sk string
	idx         u32
}

fn test_fors_skgen() ! {
	tests := [
		ForsSKGenTest{'00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', '5119e92f1e3a5f02e86b2d2fad9f8f12', 1},
		ForsSKGenTest{'ffffffffffffffffffffffffffffffff', '00000000000000000000000000000000', 'f594fbd328494c749789eefe1bf6674b', 1},
		ForsSKGenTest{'00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', 'daf49383606b6585fcf94a0d59fb281b', 0xC0FFEE},
		ForsSKGenTest{'ffffffffffffffffffffffffffffffff', '00000000000000000000000000000000', '6dfd40cea244d8aff8edb9e252871c36', 0xC0FFEE},
	]
	c := new_context(.shake_128f)
	for item in tests {
		skseed := hex.decode(item.skseed)!
		pkseed := hex.decode(item.pkseed)!
		expected_sk := hex.decode(item.expected_sk)!
		addr := new_address()
		// fors_skgen(c &Context, skseed []u8, pkseed []u8, addr Address, idx u32) ![]u8
		node := fors_skgen(c, skseed, pkseed, addr, item.idx)!
		assert expected_sk == node
	}
}
