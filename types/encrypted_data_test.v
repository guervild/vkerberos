module types

import asn1
import krb_crypto
import encoding.hex

fn test_unpack_encrypted_data() ! {
	data := hex.decode('3023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765')!

	out := asn1.der_decode(data) or { return error('error decoding data as asn1 : ${err}') }
	inner_seq := out.as_sequence() or { return error('error decoding data as sequence: ${err}') }

	e := EncryptedData.from_asn1_sequence(inner_seq)!

	assert e.etype == 0
	assert e.kvno == 5
	assert e.cipher == "krbASN.1 test message".bytes()
}
