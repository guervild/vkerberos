module types

import asn1
import constants.nametype

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.2

// PrincipalName represents Kerberos type `PrincipalName`.
// See https://tools.ietf.org/html/rfc4120#section-5.2.2
pub struct PrincipalName {
pub mut:
	name_type   int
	name_string []string
}

// PrincipalName.new_krbtgt_name returns a PrincipalName for krbtgt service type.
pub fn PrincipalName.new_krbtgt_name(domain string) !PrincipalName {
	return PrincipalName{
		name_type: nametype.krb_nt_srv_inst
		name_string: ['krbtgt', domain]
	}
}

// PrincipalName.from_bytes returns a PrincipalName given a byte array.
// `data` must corresponds to an ASN1 sequence (ASN1 representation of PrincipalName)
pub fn PrincipalName.from_bytes(data []u8) !PrincipalName {
	mut pn := PrincipalName{}

	out := asn1.der_decode(data)!

	principal_name_seq := out.as_sequence()!

	n_tagged := principal_name_seq.elements()[0].as_tagged()!
	n := n_tagged.as_inner().as_integer()!

	pn.name_type = n as int

	name_string_tagged := principal_name_seq.elements()[1].as_tagged()!
	name_string_seq := name_string_tagged.as_inner().as_sequence()!

	for e in name_string_seq.elements() {
		s := e.as_generalstring()!
		pn.name_string << string(s)
	}

	return pn
}

// PrincipalName.asn1 returns the ASN1 representation of PrincipalName.
// PrincipalName   ::= SEQUENCE {
//         name-type       [0] Int32,
//         name-string     [1] SEQUENCE OF KerberosString
// }
pub fn (pn PrincipalName) asn1() asn1.Encoder {
	mut seq := asn1.new_sequence()

	seq.add(asn1.new_explicit_context(asn1.new_integer(pn.name_type), 0))

	mut seq2 := asn1.new_sequence()

	for item in pn.name_string {
		obj := asn1.new_asn_object(asn1.Class.universal, false, 27, item.bytes())
		seq2.add(obj)
	}

	seq.add(asn1.new_explicit_context(seq2, 1))

	return seq
}

// pack returns PrincipalName ANS1 representation as an array of bytes
pub fn (pn PrincipalName) pack() ![]u8 {
	out := pn.asn1()

	return out.encode()!
}
