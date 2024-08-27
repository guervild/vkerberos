module types

import encoding.hex
import constants.nametype

fn test_pack_principal_name() {
	data := hex.decode('3018a003020101a111300f1b066866747361691b056578747261')!

	pn := PrincipalName{
		name_type: nametype.krb_nt_principal
		name_string: ['hftsai', 'extra']
	}

	out := pn.asn1()

	assert out.encode()! == data
}

fn test_unpack_principal_name() ! {
	data := hex.decode('3018a003020101a111300f1b066866747361691b056578747261')!

	pn := PrincipalName.from_bytes(data)!

	assert pn.name_type == nametype.krb_nt_principal
	assert pn.name_string == ['hftsai', 'extra']
}
