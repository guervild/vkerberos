module types

import asn1
import krb_crypto
import constants.patype

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.9
pub struct EncryptedData {
pub mut:
	etype  int
	kvno   u32
	cipher []u8
}

pub fn EncryptedData.new_encrypted_data(data []u8, key EncryptionKey, usage u32, kvno int) !EncryptedData {
	if key.key_type == 0 {
		return EncryptedData{
			etype: 0
			cipher: data
			kvno: u32(kvno)
		}
	}

	etype := krb_crypto.get_etype(key.key_type)!

	new_message := etype.encrypt_message(key.key_value, data, usage)!

	return EncryptedData{
		etype: key.key_type
		cipher: new_message
		kvno: u32(kvno)
	}
}

pub fn EncryptedData.from_asn1_sequence(seq asn1.Sequence) !EncryptedData {
	// enc_part_seq := seq.as_inner().as_sequence()!
	// TODO: check if sequence
	mut e := EncryptedData{}

	for part in seq.elements() {
		inside_tagged := part.as_tagged()!
		inside__number := inside_tagged.tag().tag_number()

		if inside__number == 0 {
			i_value := inside_tagged.as_inner().as_integer()!
			e.etype = i_value as int
		}
		if inside__number == 1 {
			ui_value := inside_tagged.as_inner().as_integer()!
			e.kvno = u32(ui_value as int)
		}
		if inside__number == 2 {
			ciph_value := inside_tagged.as_inner().as_octetstring()!
			e.cipher = ciph_value.bytes()
		}
	}

	return e
}

pub fn (e EncryptedData) asn1() asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(e.etype), 0))
	seq.add(asn1.new_explicit_context(asn1.new_integer(int(e.kvno)), 1))
	seq.add(asn1.new_explicit_context(asn1.new_octetstring(e.cipher.bytestr()), 2))

	return seq
}

pub fn (e EncryptedData) pack() ![]u8 {
	out := e.asn1()

	return out.encode()!
}

pub struct EncryptionKey {
pub mut:
	key_type  int
	key_value []u8
}

pub fn EncryptionKey.get_key_from_password(passwd string, cname PrincipalName, realm string, etype_id int, pas []PAData) !EncryptionKey {
	mut etype := krb_crypto.get_etype(etype_id)!

	mut salt := ''
	mut sk2params := etype.get_default_string_to_key_params()

	for pa in pas {
		if pa.pa_data_type == patype.pa_pw_salt {
			salt = pa.pa_data_value.bytestr()
		} else if pa.pa_data_type == patype.pa_etype_info {
			// e :=  EtypeInfo.
			// TODO FIXME
			// return error("ETYPEINFO not supported")
			continue
		} else if pa.pa_data_type == patype.pa_etype_info2 {
			e := EtypeInfo2.from_padata(pa)!

			if etype_id != e[0].etype {
				etype = krb_crypto.get_etype(etype_id)!
			}

			if e[0].sk2params.len == 4 {
				sk2params = e[0].sk2params.hex()
			}

			salt = e[0].salt
		} else {
			// return error("${pa.pa_data_type} not supported")
		}
	}

	if salt == '' {
		mut sb := []u8{}
		sb << realm.bytes()
		for n in cname.name_string {
			sb << n.bytes()
		}
		salt = sb.bytestr()
	}

	k := etype.string_to_key(passwd, salt, sk2params)!

	return EncryptionKey{
		key_type: etype_id
		key_value: k
	}
}

pub fn EncryptionKey.from_bytes(data []u8) !EncryptionKey {
	mut enc_key := EncryptionKey{}
	out := asn1.der_decode(data)!

	seq := out.as_sequence()!
	elements := seq.elements()

	for item in elements {
		curr_tagged := item.as_tagged()!
		curr_number := curr_tagged.tag().tag_number()

		if curr_number == 0 {
			n := curr_tagged.as_inner().as_integer()!
			enc_key.key_type = n as int
		}

		if curr_number == 1 {
			oc := curr_tagged.as_inner().as_octetstring()!
			enc_key.key_value = oc.bytes()
		}
	}

	return enc_key
}

pub fn (e EncryptionKey) asn1() asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(e.key_type), 0))
	seq.add(asn1.new_explicit_context(asn1.new_octetstring(e.key_value.bytestr()), 1))

	return seq
}
