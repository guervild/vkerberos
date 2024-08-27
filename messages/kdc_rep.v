module messages

import time
import asn1
import types { EncryptedData, EncryptionKey, HostAddresses, PAData, PrincipalName }
import krb_crypto
import constants
import constants.msgtype

// https://datatracker.ietf.org/doc/html/rfc1510#section-5.4.2
pub struct KDCRep {
pub mut:
	pvno               int
	msg_type           int
	pa_data            []PAData
	crealm             string
	cname              PrincipalName
	ticket             Ticket
	enc_part           EncryptedData
	decrypted_enc_part EncKDCRepPart
}

pub struct LastReq {
pub mut:
	lr_type  int
	lr_value time.Time
}

pub struct EncKDCRepPart {
pub mut:
	key            EncryptionKey
	last_reqs      []LastReq
	nonce          int
	key_expiration time.Time
	flags          []u8
	auth_time      time.Time
	start_time     time.Time
	end_time       time.Time
	renew_till     time.Time
	srealm         string
	sname          PrincipalName
	caddr          HostAddresses
	enc_padata     []PAData
}

pub fn KDCRep.from_bytes(data []u8) !KDCRep {
	mut k := KDCRep{}

	out := asn1.der_decode(data)!

	seq := out.as_sequence()!
	elements := seq.elements()

	for item in elements {
		curr_tagged := item.as_tagged()!
		curr_number := curr_tagged.tag().tag_number()

		if curr_number == 0 {
			n := curr_tagged.as_inner().as_integer()!
			k.pvno = n as int
		}

		if curr_number == 1 {
			n := curr_tagged.as_inner().as_integer()!
			k.msg_type = n as int
		}

		if curr_number == 2 {
			padata_seq := curr_tagged.as_inner().as_sequence()!

			mut padata_arr := []PAData{}

			for curr_padata in padata_seq.elements() {
				mut pa := PAData.from_bytes(curr_padata.encode()!)!

				padata_arr << pa
			}

			k.pa_data = padata_arr
		}

		if curr_number == 3 {
			s := curr_tagged.as_inner().as_generalstring()!
			k.crealm = string(s)
		}

		if curr_number == 4 {
			principal_name_seq := curr_tagged.as_inner().as_sequence()!
			pn := PrincipalName.from_bytes(principal_name_seq.encode()!)!
			k.cname = pn
		}

		if curr_number == 5 {
			ticket_obj := curr_tagged.as_inner().as_asn1object()!
			k.ticket = Ticket.from_bytes(ticket_obj.encode()!)!
		}

		if curr_number == 6 {
			in_seq := curr_tagged.as_inner().as_sequence()!
			k.enc_part = types.EncryptedData.from_asn1_sequence(in_seq)!
		}
	}

	return k
}

pub fn (k KDCRep) credentials() KRBCred {
	mut info := k.decrypted_enc_part.krbcredinfo()
	info.prealm = k.crealm
	info.pname = k.cname

	cred := KRBCred{
		pvno: constants.pvno
		msg_type: msgtype.krb_cred
		tickets: [k.ticket]
		decrypted_enc_part: EncKrbCredPart{
			ticket_info: [info]
		}
	}

	return cred
}

pub fn (mut k KDCRep) decrypt_enc_part(key EncryptionKey, usage u32) ! {
	etype := krb_crypto.get_etype(key.key_type)!

	dec := etype.decrypt_message(key.key_value, k.enc_part.cipher, u32(usage))!

	k.decrypted_enc_part = EncKDCRepPart.from_bytes(dec)!
}

fn LastReq.from_bytes(data []u8) ![]LastReq {
	mut last_reqs := []LastReq{}
	out := asn1.der_decode(data)!

	seq := out.as_sequence()!
	elements := seq.elements()

	for item in elements {
		mut last_req := LastReq{}
		inner_seq := item.as_sequence()!
		inner_elements := inner_seq.elements()

		for iner_item in inner_elements {
			curr_tagged := iner_item.as_tagged()!
			curr_number := curr_tagged.tag().tag_number()

			if curr_number == 0 {
				n := curr_tagged.as_inner().as_integer()!
				last_req.lr_type = n as int
			}

			if curr_number == 1 {
				s := curr_tagged.as_inner().as_asn1object()!
				t := types.from_keberos_time(s.values.bytestr())!
				last_req.lr_value = t
			}
		}

		last_reqs << last_req
	}

	return last_reqs
}

fn EncKDCRepPart.from_bytes(data []u8) !EncKDCRepPart {
	mut enc_kdc_rep := EncKDCRepPart{}

	out := asn1.der_decode(data)!
	obj := out.as_asn1object()!

	decoded_kdc_part := asn1.der_decode(obj.values)!


	seq := decoded_kdc_part.as_sequence()!

	elements := seq.elements()

	for item in elements {
		curr_tagged := item.as_tagged()!
		curr_number := curr_tagged.tag().tag_number()

		if curr_number == 0 {
			e := curr_tagged.as_inner().as_sequence()!
			key := EncryptionKey.from_bytes(e.encode()!)!
			enc_kdc_rep.key = key
		}

		if curr_number == 1 {
			encoded_last_reqs := curr_tagged.as_inner().as_sequence()!
			enc_kdc_rep.last_reqs = LastReq.from_bytes(encoded_last_reqs.encode()!)!
		}

		if curr_number == 2 {
			i_value := curr_tagged.as_inner().as_integer()!
			enc_kdc_rep.nonce = i_value as int
		}

		if curr_number == 3 {
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			enc_kdc_rep.key_expiration = t
		}

		if curr_number == 4 {
			b := curr_tagged.as_inner().as_bitstring()!
			enc_kdc_rep.flags = b.bytes()
		}

		if curr_number == 5 {
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			enc_kdc_rep.auth_time = t
		}

		if curr_number == 6 {
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			enc_kdc_rep.start_time = t
		}

		if curr_number == 7 {
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			enc_kdc_rep.end_time = t
		}

		if curr_number == 8 {
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			enc_kdc_rep.renew_till = t
		}

		if curr_number == 9 {
			s := curr_tagged.as_inner().as_generalstring()!
			enc_kdc_rep.srealm = string(s)
		}

		if curr_number == 10 {
			s := curr_tagged.as_inner().as_sequence()!
			pn := PrincipalName.from_bytes(s.encode()!)!
			enc_kdc_rep.sname = pn
		}

		if curr_number == 11 {
			// TODO: HostAdresses
		}
	}

	return enc_kdc_rep
}

fn (e EncKDCRepPart) krbcredinfo() KrbCredInfo {
	return KrbCredInfo{
		key: e.key
		flags: e.flags
		auth_time: e.auth_time
		start_time: e.start_time
		end_time: e.end_time
		renew_till: e.renew_till
		srealm: e.srealm
		sname: e.sname
	}
}