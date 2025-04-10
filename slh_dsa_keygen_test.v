module pslhdsa

import encoding.hex

struct KeygenTest {
	kind    Kind
	sk_seed string
	sk_prf  string
	pk_seed string

	sk_out string
	pk_out string
}

const keygen_samples = [
	KeygenTest{
		kind:    .shake_128s // SLH-DSA-SHAKE-128s
		sk_seed: '2A2CCF3CD8F9F86E131BE654CFF6C0B4'
		sk_prf:  'FDFCEB1AA2F0BA2C3C1388194F6116C7'
		pk_seed: '890CC7F4A46FE6C34D3F26A62FF962E1'
		sk_out:  '2A2CCF3CD8F9F86E131BE654CFF6C0B4FDFCEB1AA2F0BA2C3C1388194F6116C7890CC7F4A46FE6C34D3F26A62FF962E1E8C88D2BDCBA6F66E50403E77FA92EFE'
		pk_out:  '890CC7F4A46FE6C34D3F26A62FF962E1E8C88D2BDCBA6F66E50403E77FA92EFE'
	},
]

fn test_basic_slh_keygen_internal() ! {
	// slh_keygen_internal(c Context, sk_seed []u8, sk_prf []u8, pk_seed []u8) !(Sk, Pk)
	for item in keygen_samples {
		c := new_context(item.kind)
		// dump(c.is_shake())
		sk_seed := hex.decode(item.sk_seed)!
		sk_prf := hex.decode(item.sk_prf)!
		pk_seed := hex.decode(item.pk_seed)!

		sk_out := hex.decode(item.sk_out)!
		pk_out := hex.decode(item.pk_out)!

		// splitted from pk_out, where its pk_seed+pk_root
		pk_root := hex.decode('E8C88D2BDCBA6F66E50403E77FA92EFE')!

		sk, pk := slh_keygen_internal(c, sk_seed, sk_prf, pk_seed)!

		assert sk.pk.root.hex() == pk_root.hex()
		// assert pk.bytes() == pk_out
	}
}
