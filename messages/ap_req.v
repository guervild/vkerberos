module messages

import asn1

import types { Authenticator, EncryptedData, EncryptionKey}
import constants
import constants.msgtype
import constants.keyusage

pub struct APReq {
	pub mut:
	pvno int
	msg_type int
	ap_options []u8
	ticket Ticket
	authenticator EncryptedData
	decrypted_authenticator Authenticator
}

//TODO: compare with rub
pub fn APReq.new_ap_req(ticket Ticket, session_key EncryptionKey, auth Authenticator) !APReq {

	mut usage := keyusage.ap_req_authenticator

	if ticket.sname.name_string[0] == 'krbtgt' {
		usage = keyusage.tgs_req_pa_tgs_req_ap_req_authenticator
	}

	ed := auth.encrypt(session_key, u32(usage), ticket.enc_part.kvno)!

	mut k_flags := []u8{len: 4}

	return APReq {
		pvno: constants.pvno
		msg_type: msgtype.krb_ap_req
		ap_options: k_flags
		ticket: ticket
		authenticator: ed
	}
}

pub fn (a APReq) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()

	seq.add(asn1.new_explicit_context(asn1.new_integer(a.pvno), 0))
	seq.add(asn1.new_explicit_context(asn1.new_integer(a.msg_type), 1))
	seq.add(asn1.new_explicit_context(asn1.new_bitstring(a.ap_options.bytestr())!, 2))
	seq.add(asn1.new_explicit_context(a.ticket.asn1()!, 3))
	seq.add(asn1.new_explicit_context(a.authenticator.asn1(), 4))

	//TODO: FIXME CONSTANTS
	return asn1.new_asn_object(.application, true, 14, seq.encode()!)

}