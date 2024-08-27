module vkerberos

import asn1
import messages
import types
import network
import constants.keyusage
import constants.nametype

pub fn s4u_to_self(kirbi messages.KRBCred, target_user string, target_spn string, dest_ip string, dest_port int) !messages.KDCRep {

	user := kirbi.decrypted_enc_part.ticket_info[0].pname

	mut suser := kirbi.decrypted_enc_part.ticket_info[0].pname
	suser.name_type = nametype.krb_nt_unknown
	domain := kirbi.decrypted_enc_part.ticket_info[0].prealm
	ticket := kirbi.tickets[0]
	session_key := kirbi.get_default_encryption_key()
	etype := kirbi.get_default_encryption_key().key_type

	mut k_flags := []u8{len: 4}
	mut tgs_req := messages.TGSReq.new_tgs_req(user, domain, suser, ticket, session_key, k_flags, [etype], false)!

	pa_user := types.PAData.new_pa_for_user(session_key.key_value, target_user, domain)!
	tgs_req.pa_data << pa_user

	tgs_req_asn1 := tgs_req.asn1()!
	mut tgs_req_asn1_encoded := tgs_req_asn1.encode()!
	net_req := network.send_bytes(dest_ip, dest_port, mut tgs_req_asn1_encoded) or { panic(err) }

	if k_err := messages.KrbError.from_bytes(net_req) {
		return k_err
	}

	out := asn1.der_decode(net_req)!
	asn1_obj := out.as_asn1object() or { return error('kdcrep not asn1object ${err}') }
	mut k := messages.KDCRep.from_bytes(asn1_obj.values)!

	k.decrypt_enc_part(session_key, u32(keyusage.tgs_rep_encpart_session_key))!

	return k
}