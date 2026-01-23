module pslhdsa

struct Glen2Test {
	n   int
	lgw int
	out int
}

fn test_gen_len2() {
	tests := [
		Glen2Test{16, 4, 3},
		Glen2Test{24, 4, 3},
		Glen2Test{32, 4, 3},
	]
	for t in tests {
		actual := gen_len2(t.n, t.lgw)
		assert t.out == actual
	}
}

struct ToIntByteTest {
	x []u8
	n u64
}

fn test_toint_and_tobyte() {
	tests := [
		ToIntByteTest{[u8(0x1)], 1},
		ToIntByteTest{[u8(0xFF)], 255},
		ToIntByteTest{[u8(0x1), 0x00], 256},
		ToIntByteTest{[u8(0xFF), 0xFF], 65535},
		ToIntByteTest{[u8(0x1), 0x00, 0x00], 65536},
	]
	for tt in tests {
		actual := to_int(tt.x, tt.x.len)
		assert tt.n == actual
		num_bytes := tt.x.len
		reverse := to_byte(actual, num_bytes)
		assert tt.x == reverse
	}
}

struct Base2expb {
	x        []u8
	b        int
	out_len  int
	expected []u32
}

fn test_base_2exp_b() {
	tests := [
		Base2expb{[u8(0x12), 0x34, 0x56, 0x78], 4, 8, [u32(1), 2, 3, 4, 5, 6, 7, 8]},
		Base2expb{[u8(0x12), 0x34, 0x56, 0x78], 16, 2, [u32(0x1234), 0x5678]},
		Base2expb{[u8(0x12), 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 16, 4, [u32(0x1234), 0x5678,
			0x9abc, 0xdef0]},
		Base2expb{[u8(0x12), 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 32, 2, [u32(0x12345678),
			0x9abcdef0]},
	]

	for tt in tests {
		actual := base_2exp_b(tt.x, tt.b, tt.out_len)
		assert tt.expected.len == actual.len
		if  tt.expected.len == actual.len {
			for i, v in tt.expected {
				assert v == actual[i]
			}
		}
	}
}
