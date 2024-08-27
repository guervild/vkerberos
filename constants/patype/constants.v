module patype

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2
pub const pa_tgs_req = int(1)
pub const pa_enc_timestamp = int(2)
pub const pa_pw_salt = int(3)

// reserved : 4
pub const pa_enc_unix_time = int(5)
pub const pa_sandia_secureid = int(6)
pub const pa_sesame = int(7)
pub const pa_osf_dce = int(8)
pub const pa_cybersafe_secureid = int(9)
pub const pa_afs3_salt = int(10)
pub const pa_etype_info = int(11)
pub const pa_sam_challenge = int(12)
pub const pa_sam_response = int(13)
pub const pa_pk_as_req_old = int(14)
pub const pa_pk_as_rep_old = int(15)
pub const pa_pk_as_req = int(16)
pub const pa_pk_as_rep = int(17)
pub const pa_pk_ocsp_response = int(18)
pub const pa_etype_info2 = int(19)
pub const pa_use_specified_kvno = int(20)
pub const pa_svr_referral_info = int(20)
pub const pa_sam_redirect = int(21)
pub const pa_get_from_typed_data = int(22)
pub const td_padata = int(22)
pub const pa_sam_etype_info = int(23)
pub const pa_alt_princ = int(24)
pub const pa_server_referral = int(25)

// unassigned : 26-29
pub const pa_sam_challenge2 = int(30)
pub const pa_sam_response2 = int(31)

// unassigned : 32-40
pub const pa_extra_tgt = int(41)

// unassigned : 42-100
pub const td_pkinit_cms_certificates = int(101)
pub const td_krb_principal = int(102)
pub const td_krb_realm = int(103)
pub const td_trusted_certifiers = int(104)
pub const td_certificate_index = int(105)
pub const td_app_defined_error = int(106)
pub const td_req_nonce = int(107)
pub const td_req_seq = int(108)
pub const td_dh_parameters = int(109)

// unassigned : 110
pub const td_cms_digest_algorithms = int(111)
pub const td_cert_digest_algorithms = int(112)

// unassigned : 113-127
pub const pa_pac_request = int(128)
pub const pa_for_user = int(129)
pub const pa_for_x509_user = int(130)
pub const pa_for_check_dups = int(131)
pub const pa_as_checksum = int(132)
pub const pa_fx_cookie = int(133)
pub const pa_authentication_set = int(134)
pub const pa_auth_set_selected = int(135)
pub const pa_fx_fast = int(136)
pub const pa_fx_error = int(137)
pub const pa_encrypted_challenge = int(138)

// unassigned : 139-140
pub const pa_otp_challenge = int(141)
pub const pa_otp_request = int(142)
pub const pa_otp_confirm = int(143)
pub const pa_otp_pin_change = int(144)
pub const pa_epak_as_req = int(145)
pub const pa_epak_as_rep = int(146)
pub const pa_pkinit_kx = int(147)
pub const pa_pku2u_name = int(148)
pub const pa_req_enc_pa_rep = int(149)
pub const pa_as_freshness = int(150)

// unassigned : 151-164
pub const pa_supported_etypes = int(165)
pub const pa_extended_error = int(166)
