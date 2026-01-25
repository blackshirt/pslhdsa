module pslhdsa

import encoding.hex

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
	for val in tests {
		skseed := hex.decode(val.skseed)
		pkseed := hex.decode(val.pkseed)
		mut adrs := new_address()
		// xmss_node(c &Context, sk_seed []u8, i u32, z u32, pk_seed []u8, mut addr Address) ![]u8
		node := xmss_node(c, skseed, 0, 3, pkseed, mut adrs)!
		assert val.expected == node
	}
}
