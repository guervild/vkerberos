module messages

import encoding.hex

pub fn test_unpack_kdc_error_generic() ! {
	
	data := hex.decode("7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A04086B72623564617461")!
	k := KrbError.from_bytes(data)!

	assert k.pvno == 5
	assert k.msg_type == 30
	assert k.ctime.str() == '1994-06-10 06:03:17'
	assert k.cusec == 123456
	assert k.stime.str() == '1994-06-10 06:03:17'
	assert k.susec == 123456
	assert k.error_code == 60
	assert k.crealm == 'ATHENA.MIT.EDU'
	assert k.cname.name_type == 1
	assert k.cname.name_string[0] == 'hftsai'
	assert k.realm == 'ATHENA.MIT.EDU'
	assert k.sname.name_type == 1
	assert k.sname.name_string[0] == 'hftsai'
	assert k.e_text == 'krb5data'
	assert k.e_data == 'krb5data'.bytes()

}
