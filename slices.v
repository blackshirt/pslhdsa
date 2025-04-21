module pslhdsa

struct Slices {
mut:
	buf  []u8
	from int
}

fn (mut s Slices) next(n int) []u8 {
	bytes := s.buf[s.from..s.from + n]
	s.from += n

	return bytes
}

fn sliced(buf []u8) Slices {
	return Slices{
		buf: buf
	}
}
