module messages

import encoding.hex
import asn1

import krb_crypto
import constants.keyusage
import constants.nametype

fn test_unpack_as_rep() ! {
	data := hex.decode('6B81EA3081E7A003020105A10302010BA22630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A3101B0E415448454E412E4D49542E454455A41A3018A003020101A111300F1B066866747361691B056578747261A55E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A6253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765')!
	out := asn1.der_decode(data)!
	asn1_obj := out.as_asn1object() or { return error('kdcrep not asn1object ${err}') }
	k := KDCRep.from_bytes(asn1_obj.values)!

	assert k.pvno == 5
	assert k.msg_type == 11
	assert k.crealm == 'ATHENA.MIT.EDU'
	assert k.cname.name_string.len == 2
	assert k.cname.name_string == ['hftsai', 'extra']
	assert k.ticket.tkt_vno == 5
	assert k.ticket.realm == 'ATHENA.MIT.EDU'
	assert k.ticket.sname.name_string.len == 2
	assert k.ticket.sname.name_string == ['hftsai', 'extra']
	assert k.enc_part.etype == 0
	assert k.enc_part.cipher.bytestr() == 'krbASN.1 test message'
}

fn test_decrypt_enckdcreppart() ! {
	mut data := hex.decode('3700775ae1f3fd16adf078d2e4c0844249fb2a716a214836328b3c248ddc088f296a555adafea098a9ae9512af0aea34a7dc568ae9da6ed295e73deb9f93eeceb1fef74fab9df45d9e7be7a3d5b3ae50269edaa8f75383771cf1e7f9ef40cf961f56b9ddae8c434da46ed2e8b301309c573f54abbb9ceded3a7507994d4b856bc6044daf4a9825f25296dfe589c034d6eb51d84c12b398511ee5d2519f48c5ad038423ddf51244f90bf7d2303e0d4e05bd11ea863b075d8c1f0e0910f0ee5a6633a7c11b184cdf623bc060ed54da308b8c3f1586685c1b1d27053d9ad116a08ab65c56d49666231160113a43e7c085f3b1604e901c825c35a8d40610fd9e7dad53cc942b79095bcd7213433bd5bbcfe9b913ff71')!

	etype := krb_crypto.RC4HMAC{}

	key := etype.string_to_key('P@ssw0rd', '', '')!

	etype_decrypt := etype.decrypt_message(key, data, u32(keyusage.as_rep_encpart))!
	enc_kdc := EncKDCRepPart.from_bytes(etype_decrypt)!

	assert enc_kdc.key.key_value.hex() == "e1324c7fd75ce3436c67c5aeff93809b"
	assert enc_kdc.last_reqs[0].lr_type == 0
	assert enc_kdc.last_reqs[0].lr_value.str()== '2024-05-06 23:00:43'
	assert enc_kdc.nonce == 690249132
	assert enc_kdc.srealm == 'ATHENA.MIT.EDU'
	assert enc_kdc.sname.name_type == nametype.krb_nt_srv_inst
	assert enc_kdc.sname.name_string == ['krbtgt', 'ATHENA.MIT.EDU']
	assert enc_kdc.auth_time.str() == '2024-05-06 23:00:43'
	assert enc_kdc.start_time.str() == '2024-05-06 23:00:43'
	assert enc_kdc.end_time.str() == '2024-05-07 09:00:43'
	assert enc_kdc.renew_till.str() == '2024-05-07 23:00:42'
}
