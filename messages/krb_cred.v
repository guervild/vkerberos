module messages

import time
import os
import encoding.base64
import asn1
import types { EncryptedData, EncryptionKey, HostAddress, HostAddresses, PrincipalName }
import constants.msgtype

pub struct KRBCred {
pub mut:
	pvno               int
	msg_type           int
	tickets            []Ticket
	enc_part           EncryptedData
	decrypted_enc_part EncKrbCredPart
}

struct EncKrbCredPart {
pub mut:
	ticket_info []KrbCredInfo
	nonce       int
	timestamp   time.Time
	usec        int
	sadress     HostAddress
	raddress    HostAddress
}

struct KrbCredInfo {
pub mut:
	key        EncryptionKey
	prealm     string
	pname      PrincipalName
	flags      []u8
	auth_time  time.Time
	start_time time.Time
	end_time   time.Time
	renew_till time.Time
	srealm     string
	sname      PrincipalName
	caddr      HostAddresses
}

pub fn KRBCred.from_base64(b64 string) !KRBCred {
	data := base64.decode(b64)
	out :=  asn1.der_decode(data)!
	asn1_obj := out.as_asn1object() or { return error('krbcred not asn1object ${err}') }
	mut k := KRBCred.from_bytes(asn1_obj.values)!
	
	enc_asn1 := asn1.der_decode(k.enc_part.cipher)!
	enc_obj := enc_asn1.as_asn1object()!
	k.decrypted_enc_part = EncKrbCredPart.from_bytes(enc_obj.values)!

	return k
}
pub fn KRBCred.from_bytes(data []u8) !KRBCred {
	mut k := KRBCred{}

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
			tickets_seq := curr_tagged.as_inner().as_sequence()!

			mut tickets := []Ticket{}

			for t in tickets_seq.elements() {
				mut ticket := Ticket.from_bytes(t.encode()!)!

				tickets << ticket
			}

			k.tickets = tickets
		}

		if curr_number == 3 {
			in_seq := curr_tagged.as_inner().as_sequence()!
			k.enc_part = types.EncryptedData.from_asn1_sequence(in_seq)!
		}
	}

	return k
}

pub fn (k KRBCred) get_default_encryption_key() EncryptionKey {
	return k.decrypted_enc_part.ticket_info[0].key
}

fn (k KRBCred) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(k.pvno), 0))
	seq.add(asn1.new_explicit_context(asn1.new_integer(k.msg_type), 1))

	// FIXME Tickets
	mut seq_tickets := asn1.new_sequence()

	for t in k.tickets {
		seq_tickets.add(t.asn1()!)
	}
	seq.add(asn1.new_explicit_context(seq_tickets, 2))

	// Fixme EncryptedData const 14
	k_enc := k.decrypted_enc_part.asn1()!
	enc_data := types.EncryptedData.new_encrypted_data(k_enc.encode()!, EncryptionKey{ key_type: 0 },
		0, 2)!
	seq.add(asn1.new_explicit_context(enc_data.asn1(), 3))

	krb_cred := asn1.new_asn_object(.application, true, msgtype.krb_cred, seq.encode()!)

	return krb_cred
}

pub fn (k KRBCred) pack() ![]u8 {
	out := k.asn1()!

	return out.encode()!
}

pub fn (k KRBCred) save_to_file(path string) ! {
	kirbi := k.pack()!

	mut f := os.create(path) or { return error('file path ${path} not writable: ${err}') }

	f.write(kirbi)!

	f.close()
}

pub fn (k KRBCred) base64() !string {
	return base64.encode(k.pack()!)
}

fn (e EncKrbCredPart) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()
	mut seq_info := asn1.new_sequence()

	for i in e.ticket_info {
		seq_info.add(i.asn1()!)
	}

	seq.add(asn1.new_explicit_context(seq_info, 0))

	// FIXME constants 29
	e_obj := asn1.new_asn_object(.application, true, 29, seq.encode()!)

	return e_obj
}

pub fn EncKrbCredPart.from_bytes(data []u8) !EncKrbCredPart {
	mut k := EncKrbCredPart{}

	out := asn1.der_decode(data)!

	seq := out.as_sequence()!
	elements := seq.elements()

	for item in elements {
		curr_tagged := item.as_tagged()!
		curr_number := curr_tagged.tag().tag_number()

		if curr_number == 0 {
			s := curr_tagged.as_inner().as_sequence()!

			for i in s.elements() {
				k.ticket_info << KrbCredInfo.from_bytes(i.encode()!)!
			}
		}

		if curr_number == 1 {
			n := curr_tagged.as_inner().as_integer()!
			k.nonce = n as int
		}

	}

	return k

}


pub fn KrbCredInfo.from_bytes(data []u8) !KrbCredInfo {
	mut k := KrbCredInfo{}

	out := asn1.der_decode(data)!

	seq := out.as_sequence()!
	elements := seq.elements()

	for item in elements {
		curr_tagged := item.as_tagged()!
		curr_number := curr_tagged.tag().tag_number()

		if curr_number == 0 {
			e := curr_tagged.as_inner().as_sequence()!
			key := EncryptionKey.from_bytes(e.encode()!)!
			k.key = key
		}

		if curr_number == 1 {
			s := curr_tagged.as_inner().as_generalstring()!
			k.prealm = string(s)
		}

		if curr_number == 2 {
			principal_name_seq := curr_tagged.as_inner().as_sequence()!
			pn := PrincipalName.from_bytes(principal_name_seq.encode()!)!
			k.pname = pn
		}

	}

	return k

}


fn (k KrbCredInfo) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(k.key.asn1(), 0))

	if k.prealm != '' {
		seq.add(asn1.new_explicit_context(asn1.new_generalstring(k.prealm)!, 1))
	}

	if k.pname != PrincipalName{} {
		seq.add(asn1.new_explicit_context(k.pname.asn1(), 2))
	}

	if k.flags.len > 0 {
		seq.add(asn1.new_explicit_context(asn1.new_bitstring(k.flags.bytestr())!, 3))
	}

	if k.auth_time != time.Time{} {
		seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.auth_time)!, 4))
	}
	if k.start_time != time.Time{} {
		seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.start_time)!, 5))
	}
	if k.end_time != time.Time{} {
		seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.end_time)!, 6))
	}
	if k.renew_till != time.Time{} {
		seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.renew_till)!, 7))
	}
	if k.srealm != '' {
		seq.add(asn1.new_explicit_context(asn1.new_generalstring(k.srealm)!, 8))
	}

	if k.sname != PrincipalName{} {
		seq.add(asn1.new_explicit_context(k.sname.asn1(), 9))
	}

	return seq
}
