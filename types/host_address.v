module types

import asn1

// HostAddress defines Kerberos type HostAddress.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.5
pub struct HostAddress {
pub mut:
	addr_type int
	address  string
}

// HostAddresses is an array of HostAddress.
pub type HostAddresses = []HostAddress

// asn1 returns the asn1 representation of a HostAddress as described in RFC 4120.
// HostAddress     ::= SEQUENCE  {
//         addr-type       [0] Int32,
//         address         [1] OCTET STRING
// }
pub fn (h HostAddress) asn1() asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(asn1.AsnInteger(h.addr_type)), 0))

	seq.add(asn1.new_explicit_context(asn1.new_octetstring(h.address), 1))

	return seq
}

// pack returns HostAddress ANS1 representation as an array of bytes
pub fn (h HostAddress) pack() ![]u8 {
	out := h.asn1()

	return out.encode()!
}
