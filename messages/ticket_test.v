module messages

import asn1

fn test_decode_encode_ticket() ! {
	data := [u8(0x61), 0x5c, 0x30, 0x5a, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x10, 0x1b, 0x0e,
		0x41, 0x54, 0x48, 0x45, 0x4e, 0x41, 0x2e, 0x4d, 0x49, 0x54, 0x2e, 0x45, 0x44, 0x55, 0xa2,
		0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x11, 0x30, 0x0f, 0x1b, 0x06, 0x68,
		0x66, 0x74, 0x73, 0x61, 0x69, 0x1b, 0x05, 0x65, 0x78, 0x74, 0x72, 0x61, 0xa3, 0x25, 0x30,
		0x23, 0xa0, 0x03, 0x02, 0x01, 0x00, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x17, 0x04, 0x15,
		0x6b, 0x72, 0x62, 0x41, 0x53, 0x4e, 0x2e, 0x31, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d,
		0x65, 0x73, 0x73, 0x61, 0x67, 0x65]

	t := Ticket.from_bytes(data)!

	assert t.tkt_vno == int(5)
	assert t.realm == string('ATHENA.MIT.EDU')
	assert t.sname.name_type == 1
	assert t.sname.name_string[0] == 'hftsai'
	assert t.sname.name_string[1] == 'extra'
	assert t.enc_part.cipher.bytestr() == 'krbASN.1 test message'
	test_asn1 := t.asn1()!

	assert data == test_asn1.encode()!
}
