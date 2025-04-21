module pslhdsa

// The enumeration type of the SLH-DSA key.
// See Table 2. SLH-DSA parameter sets of the Chapter 11. Parameter Sets<br>
// Each sets name indicates:
//
// 	- the hash function family (SHA2 or SHAKE) that is used to instantiate the hash functions.
//	- the length in bits of the security parameter, in the 128, 192, and 256 respectives number.
//	- the mnemonic name indicates parameter to create relatively small signatures (`s`)
//	  or to have relatively fast signature generation (`f`).
pub enum Kind {
	// SHA2-based family
	sha2_128s
	sha2_128f
	sha2_192s
	sha2_192f
	sha2_256s
	sha2_256f
	// SHAKE-based family
	shake_128s
	shake_128f
	shake_192s
	shake_192f
	shake_256s
	shake_256f
}

@[inline]
fn (k Kind) is_shake() bool {
	match k {
		.shake_128s, .shake_128f, .shake_192s, .shake_192f, .shake_256s, .shake_256f { return true }
		else { return false }
	}
}

fn kind_from_longname(s string) !Kind {
	match s {
		// SHA2-based family
		'SLH-DSA-SHA2-128s' { return .sha2_128s }
		'SLH-DSA-SHA2-128f' { return .sha2_128f }
		'SLH-DSA-SHA2-192s' { return .sha2_192s }
		'SLH-DSA-SHA2-192f' { return .sha2_192f }
		'SLH-DSA-SHA2-256s' { return .sha2_256s }
		'SLH-DSA-SHA2-256f' { return .sha2_256f }
		// SHAKE-based family
		'SLH-DSA-SHAKE-128s' { return .shake_128s }
		'SLH-DSA-SHAKE-128f' { return .shake_128f }
		'SLH-DSA-SHAKE-192s' { return .shake_192s }
		'SLH-DSA-SHAKE-192f' { return .shake_192f }
		'SLH-DSA-SHAKE-256s' { return .shake_256s }
		'SLH-DSA-SHAKE-256f' { return .shake_256f }
		else { return error('Unsupported long name string') }
	}
}

fn (n Kind) long_name() string {
	match n {
		// SHA2-based family
		.sha2_128s { return 'SLH-DSA-SHA2-128s' }
		.sha2_128f { return 'SLH-DSA-SHA2-128f' }
		.sha2_192s { return 'SLH-DSA-SHA2-192s' }
		.sha2_192f { return 'SLH-DSA-SHA2-192f' }
		.sha2_256s { return 'SLH-DSA-SHA2-256s' }
		.sha2_256f { return 'SLH-DSA-SHA2-256f' }
		// SHAKE-based family
		.shake_128s { return 'SLH-DSA-SHAKE-128s' }
		.shake_128f { return 'SLH-DSA-SHAKE-128f' }
		.shake_192s { return 'SLH-DSA-SHAKE-192s' }
		.shake_192f { return 'SLH-DSA-SHAKE-192f' }
		.shake_256s { return 'SLH-DSA-SHAKE-256s' }
		.shake_256f { return 'SLH-DSA-SHAKE-256f' }
	}
}

fn (n Kind) str() string {
	match n {
		// SHA2-based family
		.sha2_128s { return 'sha2_128s' }
		.sha2_128f { return 'sha2_128f' }
		.sha2_192s { return 'sha2_192s' }
		.sha2_192f { return 'sha2_192f' }
		.sha2_256s { return 'sha2_256s' }
		.sha2_256f { return 'sha2_256f' }
		// SHAKE-based family
		.shake_128s { return 'shake_128s' }
		.shake_128f { return 'shake_128f' }
		.shake_192s { return 'shake_192s' }
		.shake_192f { return 'shake_192f' }
		.shake_256s { return 'shake_256s' }
		.shake_256f { return 'shake_256f' }
	}
}

struct ParamSet {
	// Chapter 11. Parameters Set
	id  string
	n   int
	h   int
	d   int
	hp  int
	a   int
	k   int
	lgw int = 4
	m   int
	sc  int
	pkb int
	sig int
}

// Table 2. SLH-DSA parameter sets
const paramset = {
	// 						     			id   𝑛  ℎ   𝑑  ℎp  𝑎  𝑘  𝑙𝑔𝑤 𝑚 sc pkb  sig
	'sha2_128s':  ParamSet{'SLH-DSA-SHA2-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'sha2_128f':  ParamSet{'SLH-DSA-SHA2-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'sha2_192s':  ParamSet{'SLH-DSA-SHA2-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'sha2_192f':  ParamSet{'SLH-DSA-SHA2-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'sha2_256s':  ParamSet{'SLH-DSA-SHA2-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'sha2_256f':  ParamSet{'SLH-DSA-SHA2-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
	// SHAKE family
	'shake_128s': ParamSet{'SLH-DSA-SHAKE-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'shake_128f': ParamSet{'SLH-DSA-SHAKE-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'shake_192s': ParamSet{'SLH-DSA-SHAKE-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'shake_192f': ParamSet{'SLH-DSA-SHAKE-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'shake_256s': ParamSet{'SLH-DSA-SHAKE-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'shake_256f': ParamSet{'SLH-DSA-SHAKE-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
}
