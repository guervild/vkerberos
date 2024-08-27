module types

import encoding.binary

import time
import asn1
import constants.patype
import constants.nametype
import constants.keyusage
import krb_crypto

// PAData represents Kerberos PA-DATA type as defined in the RFC.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7
pub struct PAData {
pub mut:
	pa_data_type  int
	pa_data_value []u8
}

// PAData.from_bytes return type PA-DATA by parsing the given data.
// `data` must be an asn1 sequence of PA-DATA.
pub fn PAData.from_bytes(data []u8) !PAData {
	mut pa := PAData{}

	out := asn1.der_decode(data)!

	inner_seq := out.as_sequence()!

	for part in inner_seq.elements() {
		inside_tagged := part.as_tagged()!
		inside__number := inside_tagged.tag().tag_number()

		if inside__number == 1 {
			i_value := inside_tagged.as_inner().as_integer()!
			pa.pa_data_type = i_value as int
		}
		if inside__number == 2 {
			data_value := inside_tagged.as_inner().as_octetstring()!
			pa.pa_data_value = data_value.bytes()
		}
	}

	return pa
}

// const pa_pac_request = int(128)

// new_kerb_pa_pac_request return type PAData corresponding to KERB-PA-PAC-REQUEST.
// See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/765795ba-9e05-4220-9bd3-b34464e413a7
pub fn PAData.new_kerb_pa_pac_request(includePac bool) !PAData {
	mut seq_pa_pac_req := asn1.new_sequence()
	seq_pa_pac_req.add(asn1.new_explicit_context(asn1.new_boolean(includePac), 0))
	// plop := [u8(0x30), 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01]
	return PAData{
		pa_data_type: patype.pa_pac_request
		pa_data_value: seq_pa_pac_req.encode()!
	}
}


pub fn PAData.new_pa_for_user(key []u8, username string, realm string) !PAData {

	auth_package := "Kerberos"

	user := types.PrincipalName{
		name_type: nametype.krb_nt_principal
		name_string: [username]
	}

	mut s4u_byte_array := []u8{}

	// put nametype
	mut b_nametype := []u8{len: 4, init: 0}
	binary.little_endian_put_u32(mut b_nametype, u32(user.name_type))
	s4u_byte_array << b_nametype

	// put namestring
	for  s in user.name_string {
		s4u_byte_array << s.bytes()
	}

	// put realm
	s4u_byte_array << realm.bytes()

	// put authpackage
	s4u_byte_array << auth_package.bytes()

	etype := krb_crypto.get_etype(krb_crypto.rc4_hmac)!
	
	cb := etype.checksum(key, s4u_byte_array, u32(keyusage.kerb_non_kerb_cksum_salt))!

	checksum := Checksum{
		cksum_type: etype.get_hash_id()
		checksum: cb
	}

	mut seq_pa_for_user := asn1.new_sequence()
	seq_pa_for_user.add(asn1.new_explicit_context(user.asn1(), 0))
	seq_pa_for_user.add(asn1.new_explicit_context(asn1.new_generalstring(realm)!, 1))
	seq_pa_for_user.add(asn1.new_explicit_context(checksum.asn1(), 2))
	seq_pa_for_user.add(asn1.new_explicit_context(asn1.new_generalstring(auth_package)!, 3))

	return PAData{
		pa_data_type: patype.pa_for_user
		pa_data_value: seq_pa_for_user.encode()!
	}
}

// asn1 returns the asn1 representation of a PAData as described in RFC.
// PA-DATA         ::= SEQUENCE {
//         -- NOTE: first tag is [1], not [0]
//         padata-type     [1] Int32,
//         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
// }
pub fn (p PAData) asn1() asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(p.pa_data_type), 1))

	seq.add(asn1.new_explicit_context(asn1.new_octetstring(p.pa_data_value.bytestr()),
		2))

	return seq
}

// pack returns PA-DATA ANS1 representation as an array of bytes
pub fn (p PAData) pack() ![]u8 {
	out := p.asn1()

	return out.encode()!
}

// PAEncTsEnc represents Kerberos PA-ENC-TS-ENC type as defined in RFC.
// This is use for pre-authentication.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.2
pub struct PAEncTsEnc {
pub mut:
	pa_time_stamp time.Time
	pa_usec       int
}

// PAEncTsEnc.new returns a new `PAEncTsEnc`
pub fn PAEncTsEnc.new() PAEncTsEnc {
	now := time.now().local_to_utc()

	return PAEncTsEnc{
		pa_time_stamp: now
		pa_usec: int((now.unix_nano() / i64(time.microsecond)) - (now.unix() * i64(1000000)))
	}
}

// to_pa_data returns the `PAData` representation of the PAEncTsEnc
pub fn (p PAEncTsEnc) to_pa_data() !PAData {
	mut seq := asn1.new_sequence()

	now_formated := p.pa_time_stamp.custom_format('YYYYMMDDHHmmss')

	seq.add(asn1.new_explicit_context(asn1.new_generalizedtime('${now_formated}Z')!, 0))
	seq.add(asn1.new_explicit_context(asn1.new_integer(int(p.pa_usec)), 1))

	return PAData{
		pa_data_type: patype.pa_enc_timestamp
		pa_data_value: seq.encode()!
	}
}

// EtypeInfoEntry represents kerberos type `ETYPE-INFO-ENTRY`.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.4
pub struct EtypeInfoEntry {
pub mut:
	etype int
	salt  []u8
}

// EtypeInfo represents kerberos type `ETYPE-INFO`.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.4
type EtypeInfo = []EtypeInfoEntry

// EtypeInfo2Entry represents kerberos type `ETYPE-INFO2-ENTRY`.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.5
pub struct EtypeInfo2Entry {
pub mut:
	etype     int
	salt      string
	sk2params []u8
}

// EtypeInfo2 represents kerberos type `ETYPE-INFO2`.
// See https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.5
type EtypeInfo2 = []EtypeInfo2Entry

// EtypeInfo2.from_padata returns a EtypeInfo2 type given a PAData.
pub fn EtypeInfo2.from_padata(pa PAData) !EtypeInfo2 {
	if pa.pa_data_type != patype.pa_etype_info2 {
		return error('error PADATA TYPE: expected ${patype.pa_etype_info} got ${pa.pa_data_type}')
	}

	return EtypeInfo2.from_bytes(pa.pa_data_value)!
}

// EtypeInfo2.from_bytes returns a EtypeInfo2 type given a byte array.
// The byte arry must corresponds to an asn1 sequence.
pub fn EtypeInfo2.from_bytes(data []u8) !EtypeInfo2 {
	mut e := EtypeInfo2{}

	out := asn1.der_decode(data) or { return error('error decoding data as asn1 : ${err}') }

	inner_seq := out.as_sequence() or { return error('error decoding data as sequence: ${err}') }

	for curr_elem in inner_seq.elements() {
		e << EtypeInfo2Entry.from_bytes(curr_elem.encode()!)!
	}

	return e
}

// EtypeInfo2Entry.from_bytes returns a EtypeInfo2Entry type given a byte array.
// The byte arry must corresponds to an asn1 sequence.
fn EtypeInfo2Entry.from_bytes(data []u8) !EtypeInfo2Entry {
	mut entry := EtypeInfo2Entry{}

	out := asn1.der_decode(data) or { return error('error decoding data as asn1 : ${err}') }
	inner_seq := out.as_sequence() or { return error('error decoding data as sequence: ${err}') }

	for part in inner_seq.elements() {
		inside_tagged := part.as_tagged() or {
			return error('error decoding data as tagged: ${err} ${part}')
		}
		inside__number := inside_tagged.tag().tag_number()

		if inside__number == 0 {
			i_value := inside_tagged.as_inner().as_integer() or {
				return error('error decoding data as integer: ${err}')
			}
			entry.etype = i_value as int
		}
		if inside__number == 1 {
			s := inside_tagged.as_inner().as_generalstring() or {
				return error('error decoding data as generalstring: ${err}')
			}
			entry.salt = string(s)
		}
		if inside__number == 2 {
			sk2params_value := inside_tagged.as_inner().as_octetstring()!
			entry.sk2params = sk2params_value.bytes()
		}
	}

	return entry
}
