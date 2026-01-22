module pslhdsa

import hash
import crypto.sha256
import crypto.sha512
import encoding.hex

struct Mgf1Test {
mut:
	name     string
	seed     string
	length   int
	h        hash.Hash
	expected string
}

const mgf1_cases = [
	Mgf1Test{
		name:     'SHA-256 Basic'
		seed:     '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
		length:   32
		h:        sha256.new()
		expected: 'c03f158d5a21c640563a1045774d5928ec4afd4cb550bb28dbbe5099cf51380a'
	},
	Mgf1Test{
		name:     'SHA-512 Basic'
		seed:     '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
		length:   64
		h:        sha512.new()
		expected: '8feff3bbf4875c9d37fb2de60fb4e1baa796032d65953a40fa0164ce89343d97' +
			'5e4b932adc52fae6466b495a35d87fe23de269da48b2a1e23dfecdca17d035ff'
	},
	Mgf1Test{
		name:     'Short output'
		seed:     '0123456789abcdef'
		length:   16
		h:        sha256.new()
		expected: '3f7ab49a79d4788372572a77de9e48b2'
	},
	Mgf1Test{
		name:     'Long output (multiple hash iterations)'
		seed:     '0123456789abcdef'
		length:   100
		h:        sha256.new()
		expected: '3f7ab49a79d4788372572a77de9e48b28833d1bbc194b70e7411682051c024bb' +
			'067ff37759348e7a82795414d0b6f53887b345aa6a5f1ec17c3110426fc8ef53' +
			'd43b8fd26b186431cbb2171f908bbdc5d4e77d86c27ef37fd87feae71a10b75422228607'
	},
]

fn test_mgf1_cases() ! {
	for mut c in mgf1_cases {
		seed := hex.decode(c.seed)!
		expected := hex.decode(c.expected)!

		result := mgf1(seed, c.length, mut c.h)!
		assert result == expected
	}
}
