module vkerberos

import asn1
import types
import messages
import network
import constants.nametype
import constants.keyusage

pub fn ask_tgt(user string, passwd string, domain string, dest_ip string, dest_port int) !messages.KDCRep {
	cname := types.PrincipalName{
		name_type: nametype.krb_nt_principal
		name_string: [user]
	}

	sname := types.PrincipalName.new_krbtgt_name(domain)!

	// set default kdc_options_flags
	mut k_flags := []u8{len: 4}
	types.set_kdc_options(mut &k_flags, types.kdcflagsforwardable)
	types.set_kdc_options(mut &k_flags, types.kdcflagsrenewable)
	types.set_kdc_options(mut &k_flags, types.kdcflagscanonicalize)
	types.set_kdc_options(mut &k_flags, types.kdcflagsrenewableok)
	
	mut pa_data := []types.PAData{}

	pa_pac := types.PAData.new_kerb_pa_pac_request(true)!

	pa_data << pa_pac

	// TODO: etypes must be a choice
	mut as_req := messages.ASReq.new_as_req(domain, cname, sname, pa_data, k_flags, [
		23,
	])!

	mut as_req_asn1 := as_req.asn1()!
	mut as_req_asn1_encoded := as_req_asn1.encode()!
	mut net_req := network.send_bytes(dest_ip, dest_port, mut as_req_asn1_encoded) or { panic(err) }

	mut k_err := messages.KrbError.from_bytes(net_req)!

	if k_err.error_code != messages.kdc_err_preauth_required
		&& k_err.error_code != messages.kdc_err_preauth_failed {
		return k_err
	}

	// TODO: own func
	rcv_edata := asn1.der_decode(k_err.e_data)!
	rcv_padata_seq := rcv_edata.as_sequence()!
	mut rcv_pas := []types.PAData{}

	for curr_padata in rcv_padata_seq.elements() {
		mut pa := types.PAData.from_bytes(curr_padata.encode()!)!
		rcv_pas << pa
	}

	// generate key
	// TODO check how to pass the first etype id
	key := types.EncryptionKey.get_key_from_password(passwd, cname, domain, 23, rcv_pas)!

	mut pa_ts := types.PAEncTsEnc.new().to_pa_data()!

	// TODO: KVNO value
	enc := types.EncryptedData.new_encrypted_data(pa_ts.pa_data_value, key, u32(keyusage.as_req_pa_enc_timestamp),
		0)!
	pa_ts.pa_data_value = enc.pack()!

	pa_data << pa_ts
	as_req.pa_data = pa_data

	as_req_asn1 = as_req.asn1()!
	as_req_asn1_encoded = as_req_asn1.encode()!
	net_req = network.send_bytes(dest_ip, dest_port, mut as_req_asn1_encoded) or { panic(err) }

	if k_err2 := messages.KrbError.from_bytes(net_req) {
		return k_err2
	}

	out := asn1.der_decode(net_req)!
	asn1_obj := out.as_asn1object() or { return error('kdcrep not asn1object ${err}') }
	mut k := messages.KDCRep.from_bytes(asn1_obj.values)!

	k.decrypt_enc_part(key, u32(keyusage.as_rep_encpart))!

	return k
}


pub fn ask_tgs(realm string, tgt messages.Ticket, session_key types.EncryptionKey, dest_ip string, dest_port int) !messages.KDCRep {
	cname := types.PrincipalName{
		name_type: nametype.krb_nt_unknown
		name_string: ['MyPC$']
	}

	sname := types.PrincipalName.new_krbtgt_name(realm)!
	
	//TODO:
	mut k_flags := []u8{len: 4}
	mut tgs_req := messages.TGSReq.new_tgs_req(cname, realm, sname, tgt, session_key, k_flags, [23], false)!

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