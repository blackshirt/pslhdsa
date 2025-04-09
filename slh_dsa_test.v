module pslhdsa

fn test_basic_signing_verifying() ! {
	ctx := new_context(.shake_128s)
	dump(ctx.prm.id.str())
	sk, pk := slh_keygen(ctx)!
	dump(sk)
	dump(pk)

	msg := 'Hello'.bytes()
	cx := []u8{}
	sig := slh_sign(ctx, msg, cx, sk)!
	dump(sig.hex())
}
