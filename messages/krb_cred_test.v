module messages

import asn1
import encoding.hex
import encoding.base64
import krb_crypto

fn test_unpack_krbcred() ! {
	data := hex.decode('7681F63081F3A003020105A103020116A281BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765')!

	out :=  asn1.der_decode(data)!
	asn1_obj := out.as_asn1object() or { return error('krbcred not asn1object ${err}') }
	k := KRBCred.from_bytes(asn1_obj.values)!
	
	assert k.pvno == 5
	assert k.msg_type == 22
	assert k.tickets[0].realm == 'ATHENA.MIT.EDU'
	assert k.tickets[0].sname.name_type == 1
	assert k.tickets[0].sname.name_string[0] == 'hftsai'
	assert k.tickets[0].enc_part.cipher.bytestr() == 'krbASN.1 test message'
}