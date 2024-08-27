module types

import asn1

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.9
// pub struct EncryptedData {
// pub mut:
//	e_type int
//	kvno   int
//	cipher []u8
//}

// pub struct EncryptionKey {
// pub mut:
// 	key_type  int
// 	key_value []u8
// }

pub struct Checksum {
pub mut:
	cksum_type int
	checksum  []u8
}

pub fn (c Checksum) asn1() asn1.Encoder {

	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(c.cksum_type), 0))
	seq.add(asn1.new_explicit_context(asn1.new_octetstring(c.checksum.bytestr()), 1))
	return seq
}

// TODO Encrypt
