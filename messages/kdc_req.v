module messages

import asn1
import time
import rand


import constants
import constants.msgtype
import constants.patype
import constants.keyusage
import krb_crypto
import types { Authenticator, Checksum, EncryptedData, EncryptionKey, HostAddress, PAData, PrincipalName }

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.1
pub struct KDCReq {
pub mut:
	pvno     int
	msg_type int
	pa_data  []PAData
	req_body KDCReqBody
	renewal  bool
}

pub struct KDCReqBody {
pub mut:
	kdc_options         []u8
	cname               PrincipalName
	realm               string
	sname               PrincipalName
	from                time.Time
	till                time.Time
	rtime               time.Time
	nonce               int // should be uint
	etype               []int
	addresses           []HostAddress
	encauthdata         EncryptedData
	additionnal_tickets []Ticket
}

pub struct ASReq {
	KDCReq
}

pub struct TGSReq {
	KDCReq
}

pub fn ASReq.new_as_req(realm string, cname PrincipalName, sname PrincipalName, pa_data []PAData, kerberos_flags []u8, enc_type []int) !ASReq {
	now := time.now()
	nonce := rand.intn(2147483647)!

	req := ASReq{KDCReq{
		pvno: constants.pvno
		msg_type: msgtype.krb_as_req
		pa_data: pa_data
		req_body: KDCReqBody{
			kdc_options: kerberos_flags
			realm: realm.to_upper() // TODO: change to uppercase ??
			cname: cname
			sname: sname
			till: now.local_to_utc().add_days(1)
			nonce: nonce
			etype: enc_type
		}
	}}

	return req
}

pub fn (k KDCReq) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()

	seq.add(asn1.new_explicit_context(asn1.new_integer(k.pvno), 1))
	seq.add(asn1.new_explicit_context(asn1.new_integer(k.msg_type), 2))

	// pa_data is optional
	if k.pa_data.len > 0 {
		mut seq_pa_data := asn1.new_sequence()

		for item in k.pa_data {
			seq_pa_data.add(item.asn1())
		}

		seq.add(asn1.new_explicit_context(seq_pa_data, 3))
	}

	seq.add(asn1.new_explicit_context(k.req_body.asn1()!, 4))

	return seq
}

//TODO constants app type
pub fn (a ASReq) asn1() !asn1.Encoder {
	req := asn1.new_asn_object(.application, true, 10, a.KDCReq.pack()!)
	return req
}

pub fn TGSReq.new_tgs_req(cname PrincipalName, realm string, sname PrincipalName, tgt Ticket, session_key EncryptionKey, kerberos_flags []u8, enc_type []int, renewal bool) !TGSReq{

	mut req := tgs_req(cname, realm, sname, kerberos_flags, enc_type, renewal)!

	req.set_pa_data(tgt, session_key)!

	return req
}

pub fn tgs_req(cname PrincipalName, realm string, sname PrincipalName, kerberos_flags []u8, enc_type []int, renewal bool) !TGSReq{
	now := time.now()
	nonce := rand.intn(2147483647)!

	mut flags := kerberos_flags.clone()

	//FIX
	if renewal {
		types.set_kdc_options(mut &flags, types.kdcflagsrenew)
		types.set_kdc_options(mut &flags, types.kdcflagsrenewable)
	}
	else {
		types.set_kdc_options(mut &flags, types.kdcflagsforwardable)
		types.set_kdc_options(mut &flags, types.kdcflagsrenewable)
		types.set_kdc_options(mut &flags, types.kdcflagscanonicalize)
		//types.set_kdc_options(mut &flags, types.kdcflagsrenewableok)
	}

	req := TGSReq{KDCReq{
		pvno: constants.pvno
		msg_type: msgtype.krb_tgs_req
		
		req_body: KDCReqBody{
			kdc_options: flags
			realm: realm.to_upper() // TODO: cuppercase ?
			cname: cname
			sname: sname
			till: now.local_to_utc().add_days(1)
			nonce: nonce
			etype: enc_type
		}

		renewal: renewal
	}}

	return req
}

pub fn (mut t TGSReq) set_pa_data(tgt Ticket, session_key EncryptionKey) ! {
	b := t.KDCReq.req_body.asn1()!

	etype := krb_crypto.get_etype(session_key.key_type)!
	
	cb := etype.checksum(session_key.key_value, b.encode()!, u32(keyusage.tgs_req_pa_tgs_req_ap_req_authenticator_chksum))!

	//PADATA for TGS-REQ
	mut auth := Authenticator.new(tgt.realm, t.KDCReq.req_body.cname)

	auth.cksum = Checksum{
		cksum_type: etype.get_hash_id()
		checksum: cb
	}

	//create ap_req
	ap_req := APReq.new_ap_req(tgt, session_key, auth)!

	ap_req_obj := ap_req.asn1()!
	new_pa := PAData {
		pa_data_type: patype.pa_tgs_req
		pa_data_value: ap_req_obj.encode()!
	}

	t.pa_data << new_pa
} 

//TODO constants app type
pub fn (t TGSReq) asn1() !asn1.Encoder {
	req := asn1.new_asn_object(.application, true, 12, t.KDCReq.pack()!)
	return req
}

pub fn (k KDCReq) pack() ![]u8 {
	out := k.asn1()!
	return out.encode()!
}

pub fn (k KDCReqBody) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()

	seq.add(asn1.new_explicit_context(asn1.new_bitstring(k.kdc_options.bytestr())!, 0))

	// cname is optional
	if k.cname != PrincipalName{} {
		seq.add(asn1.new_explicit_context(k.cname.asn1(), 1))
	}

	seq.add(asn1.new_explicit_context(asn1.new_asn_object(asn1.Class.universal, false,
		27, k.realm.bytes()), 2))

	seq.add(asn1.new_explicit_context(k.sname.asn1(), 3))

	// from is optional
	if k.from != time.Time{} {
		seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.from)!, 4))
	}

	seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.till)!, 5))

	// rtime is optional
	if k.rtime != time.Time{} {
		seq.add(asn1.new_explicit_context(types.to_kerberos_time(k.rtime)!, 6))
	}

	seq.add(asn1.new_explicit_context(asn1.new_integer(k.nonce), 7))

	mut seq_etype := asn1.new_sequence()

	for e in k.etype {
		seq_etype.add(asn1.new_integer(asn1.AsnInteger(e)))
	}

	seq.add(asn1.new_explicit_context(seq_etype, 8))

	if k.addresses.len > 0 {
		mut seq3 := asn1.new_sequence()

		for h in k.addresses {
			seq3.add(h.asn1())
		}

		seq.add(asn1.new_explicit_context(seq3, 9))
	}

	if k.encauthdata != EncryptedData{} {
		seq.add(asn1.new_explicit_context(k.encauthdata.asn1(), 10))
	}

	if k.additionnal_tickets.len > 0 {
		mut seq_tickets := asn1.new_sequence()
		for t in k.additionnal_tickets {
			seq_tickets.add(t.asn1()!)
		}

		seq.add(asn1.new_explicit_context(seq_tickets, 11))
	}

	return seq
}

pub fn (k KDCReqBody) pack() ![]u8 {
	out := k.asn1()!

	return out.encode()!
}
