module messages

import time
import asn1
import types { PrincipalName }

pub struct KrbError {
	Error
pub mut:
	pvno       int
	msg_type   int
	ctime      time.Time
	cusec      int // Microseconds
	stime      time.Time
	susec      int // Microseconds
	error_code int
	crealm     string
	cname      PrincipalName
	realm      string
	sname      PrincipalName
	e_text     string
	e_data     []u8
}

pub fn KrbError.from_bytes(data []u8) !KrbError {
	mut k := KrbError{}
	out := asn1.der_decode(data)!

	application := out.as_asn1object()!

	decoded_seq := asn1.der_decode(application.values)!
	seq := decoded_seq.as_sequence()!
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
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			k.ctime = t
		}

		if curr_number == 3 {
			n := curr_tagged.as_inner().as_integer()!
			k.cusec = n as int
		}
		// should be a generalizedtime but its asn1object
		if curr_number == 4 {
			s := curr_tagged.as_inner().as_asn1object()!
			t := types.from_keberos_time(s.values.bytestr())!
			k.stime = t
		}

		if curr_number == 5 {
			n := curr_tagged.as_inner().as_integer()!
			k.susec = n as int
		}

		if curr_number == 6 {
			n := curr_tagged.as_inner().as_integer()!
			k.error_code = n as int
		}


		if curr_number == 7 {
			s := curr_tagged.as_inner().as_generalstring()!
			k.crealm = string(s)
		}

		if curr_number == 8 {
			principal_name_seq := curr_tagged.as_inner().as_sequence()!

			pn := PrincipalName.from_bytes(principal_name_seq.encode()!)!
			k.cname = pn
			// k.crealm = s.values.bytestr()
		}

		if curr_number == 9 {
			s := curr_tagged.as_inner().as_generalstring()!
			k.realm = string(s)
		}

		if curr_number == 10 {
			principal_name_seq := curr_tagged.as_inner().as_sequence()!

			pn := PrincipalName.from_bytes(principal_name_seq.encode()!)!
			k.sname = pn
		}

		if curr_number == 11 {
			s := curr_tagged.as_inner().as_generalstring()!
			k.e_text = string(s)
		}

		// TODO: E-DATA OCTET STRING
		if curr_number == 12 {
			e := curr_tagged.as_inner().as_octetstring()!
			k.e_data = e.bytes()
		}
	}

	return k
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
pub const kdc_err_none = int(0) // No error

pub const kdc_err_name_exp = int(1) // Client's entry in database has expired

pub const kdc_err_service_exp = int(2) // Server's entry in database has expired

pub const kdc_err_bad_pvno = int(3) // Requested protocol version number not supported

pub const kdc_err_c_old_mast_kvno = int(4) // Client's key encrypted in old master key

pub const kdc_err_s_old_mast_kvno = int(5) // Server's key encrypted in old master key

pub const kdc_err_c_principal_unknown = int(6) // Client not found in Kerberos database

pub const kdc_err_s_principal_unknown = int(7) // Server not found in Kerberos database

pub const kdc_err_principal_not_unique = int(8) // Multiple principal entries in database

pub const kdc_err_null_key = int(9) // The client or server has a null key

pub const kdc_err_cannot_postdate = int(10) // Ticket not eligible for postdating

pub const kdc_err_never_valid = int(11) // Requested starttime is later than end time

pub const kdc_err_policy = int(12) // KDC policy rejects request

pub const kdc_err_badoption = int(13) // KDC cannot accommodate requested option

pub const kdc_err_etype_nosupp = int(14) // KDC has no support for encryption type

pub const kdc_err_sumtype_nosupp = int(15) // KDC has no support for checksum type

pub const kdc_err_padata_type_nosupp = int(16) // KDC has no support for padata type

pub const kdc_err_trtype_nosupp = int(17) // KDC has no support for transited type

pub const kdc_err_client_revoked = int(18) // Clients credentials have been revoked

pub const kdc_err_service_revoked = int(19) // Credentials for server have been revoked

pub const kdc_err_tgt_revoked = int(20) // TGT has been revoked

pub const kdc_err_client_notyet = int(21) // Client not yet valid; try again later

pub const kdc_err_service_notyet = int(22) // Server not yet valid; try again later

pub const kdc_err_key_expired = int(23) // Password has expired; change password to reset

pub const kdc_err_preauth_failed = int(24) // Pre-authentication information was invalid

pub const kdc_err_preauth_required = int(25) // Additional pre-authentication required

pub const kdc_err_server_nomatch = int(26) // Requested server and ticket don't match

pub const kdc_err_must_use_user2user = int(27) // Server principal valid for user2user only

pub const kdc_err_path_not_accepted = int(28) // KDC Policy rejects transited path

pub const kdc_err_svc_unavailable = int(29) // A service is not available

pub const krb_ap_err_bad_integrity = int(31) // Integrity check on decrypted field failed

pub const krb_ap_err_tkt_expired = int(32) // Ticket expired

pub const krb_ap_err_tkt_nyv = int(33) // Ticket not yet valid

pub const krb_ap_err_repeat = int(34) // Request is a replay

pub const krb_ap_err_not_us = int(35) // The ticket isn't for us

pub const krb_ap_err_badmatch = int(36) // Ticket and authenticator don't match

pub const krb_ap_err_skew = int(37) // Clock skew too great

pub const krb_ap_err_badaddr = int(38) // Incorrect net address

pub const krb_ap_err_badversion = int(39) // Protocol version mismatch

pub const krb_ap_err_msg_type = int(40) // Invalid msg type

pub const krb_ap_err_modified = int(41) // Message stream modified

pub const krb_ap_err_badorder = int(42) // Message out of order

pub const krb_ap_err_badkeyver = int(44) // Specified version of key is not available

pub const krb_ap_err_nokey = int(45) // Service key not available

pub const krb_ap_err_mut_fail = int(46) // Mutual authentication failed

pub const krb_ap_err_baddirection = int(47) // Incorrect message direction

pub const krb_ap_err_method = int(48) // Alternative authentication method required

pub const krb_ap_err_badseq = int(49) // Incorrect sequence number in message

pub const krb_ap_err_inapp_cksum = int(50) // Inappropriate type of checksum in message

pub const krb_ap_path_not_accepted = int(51) // Policy rejects transited path

pub const krb_err_response_too_big = int(52) // Response too big for UDP;  retry with TCP

pub const krb_err_generic = int(60) // Generic error (description in e-text)

pub const krb_err_field_toolong = int(61) // Field is too long for this implementation

pub const kdc_error_client_not_trusted = int(62) // Reserved for PKINIT

pub const kdc_error_kdc_not_trusted = int(63) // Reserved for PKINIT

pub const kdc_error_invalid_sig = int(64) // Reserved for PKINIT

pub const kdc_err_key_too_weak = int(65) // Reserved for PKINIT

pub const kdc_err_certificate_mismatch = int(66) // Reserved for PKINIT

pub const krb_ap_err_no_tgt = int(67) // No TGT available to validate USER-TO-USER

pub const kdc_err_wrong_realm = int(68) // Reserved for future use

pub const krb_ap_err_user_to_user_required = int(69) // Ticket must be for USER-TO-USER

pub const kdc_err_cant_verify_certificate = int(70) // Reserved for PKINIT

pub const kdc_err_invalid_certificate = int(71) // Reserved for PKINIT

pub const kdc_err_revoked_certificate = int(72) // Reserved for PKINIT

pub const kdc_err_revocation_status_unknown = int(73) // Reserved for PKINIT

pub const kdc_err_revocation_status_unavailable = int(74) // Reserved for PKINIT

pub const kdc_err_client_name_mismatch = int(75) // Reserved for PKINIT

pub const kdc_err_kdc_name_mismatch = int(76) // Reserved for PKINIT

const error_code_by_id = {
	kdc_err_none:                          'KDC_ERR_NONE No error'
	kdc_err_name_exp:                      "KDC_ERR_NAME_EXP Client's entry in database has expired"
	kdc_err_service_exp:                   "KDC_ERR_SERVICE_EXP Server's entry in database has expired"
	kdc_err_bad_pvno:                      'KDC_ERR_BAD_PVNO Requested protocol version number not supported'
	kdc_err_c_old_mast_kvno:               "KDC_ERR_C_OLD_MAST_KVNO Client's key encrypted in old master key"
	kdc_err_s_old_mast_kvno:               "KDC_ERR_S_OLD_MAST_KVNO Server's key encrypted in old master key"
	kdc_err_c_principal_unknown:           'KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database'
	kdc_err_s_principal_unknown:           'KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found in Kerberos database'
	kdc_err_principal_not_unique:          'KDC_ERR_PRINCIPAL_NOT_UNIQUE Multiple principal entries in database'
	kdc_err_null_key:                      'KDC_ERR_NULL_KEY The client or server has a null key'
	kdc_err_cannot_postdate:               'KDC_ERR_CANNOT_POSTDATE Ticket not eligible for postdating'
	kdc_err_never_valid:                   'KDC_ERR_NEVER_VALID Requested starttime is later than end time'
	kdc_err_policy:                        'KDC_ERR_POLICY KDC policy rejects request'
	kdc_err_badoption:                     'KDC_ERR_BADOPTION KDC cannot accommodate requested option'
	kdc_err_etype_nosupp:                  'KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type'
	kdc_err_sumtype_nosupp:                'KDC_ERR_SUMTYPE_NOSUPP KDC has no support for checksum type'
	kdc_err_padata_type_nosupp:            'KDC_ERR_PADATA_TYPE_NOSUPP KDC has no support for padata type'
	kdc_err_trtype_nosupp:                 'KDC_ERR_TRTYPE_NOSUPP KDC has no support for transited type'
	kdc_err_client_revoked:                'KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked'
	kdc_err_service_revoked:               'KDC_ERR_SERVICE_REVOKED Credentials for server have been revoked'
	kdc_err_tgt_revoked:                   'KDC_ERR_TGT_REVOKED TGT has been revoked'
	kdc_err_client_notyet:                 'KDC_ERR_CLIENT_NOTYET Client not yet valid; try again later'
	kdc_err_service_notyet:                'KDC_ERR_SERVICE_NOTYET Server not yet valid; try again later'
	kdc_err_key_expired:                   'KDC_ERR_KEY_EXPIRED Password has expired; change password to reset'
	kdc_err_preauth_failed:                'KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid'
	kdc_err_preauth_required:              'KDC_ERR_PREAUTH_REQUIRED Additional pre-authentication required'
	kdc_err_server_nomatch:                "KDC_ERR_SERVER_NOMATCH Requested server and ticket don't match"
	kdc_err_must_use_user2user:            'KDC_ERR_MUST_USE_USER2USER Server principal valid for  user2user only'
	kdc_err_path_not_accepted:             'KDC_ERR_PATH_NOT_ACCEPTED KDC Policy rejects transited path'
	kdc_err_svc_unavailable:               'KDC_ERR_SVC_UNAVAILABLE A service is not available'
	krb_ap_err_bad_integrity:              'KRB_AP_ERR_BAD_INTEGRITY Integrity check on decrypted field failed'
	krb_ap_err_tkt_expired:                'KRB_AP_ERR_TKT_EXPIRED Ticket expired'
	krb_ap_err_tkt_nyv:                    'KRB_AP_ERR_TKT_NYV Ticket not yet valid'
	krb_ap_err_repeat:                     'KRB_AP_ERR_REPEAT Request is a replay'
	krb_ap_err_not_us:                     "KRB_AP_ERR_NOT_US The ticket isn't for us"
	krb_ap_err_badmatch:                   "KRB_AP_ERR_BADMATCH Ticket and authenticator don't match"
	krb_ap_err_skew:                       'KRB_AP_ERR_SKEW Clock skew too great'
	krb_ap_err_badaddr:                    'KRB_AP_ERR_BADADDR Incorrect net address'
	krb_ap_err_badversion:                 'KRB_AP_ERR_BADVERSION Protocol version mismatch'
	krb_ap_err_msg_type:                   'KRB_AP_ERR_MSG_TYPE Invalid msg type'
	krb_ap_err_modified:                   'KRB_AP_ERR_MODIFIED Message stream modified'
	krb_ap_err_badorder:                   'KRB_AP_ERR_BADORDER Message out of order'
	krb_ap_err_badkeyver:                  'KRB_AP_ERR_BADKEYVER Specified version of key is not available'
	krb_ap_err_nokey:                      'KRB_AP_ERR_NOKEY Service key not available'
	krb_ap_err_mut_fail:                   'KRB_AP_ERR_MUT_FAIL Mutual authentication failed'
	krb_ap_err_baddirection:               'KRB_AP_ERR_BADDIRECTION Incorrect message direction'
	krb_ap_err_method:                     'KRB_AP_ERR_METHOD Alternative authentication method required'
	krb_ap_err_badseq:                     'KRB_AP_ERR_BADSEQ Incorrect sequence number in message'
	krb_ap_err_inapp_cksum:                'KRB_AP_ERR_INAPP_CKSUM Inappropriate type of checksum in message'
	krb_ap_path_not_accepted:              'KRB_AP_PATH_NOT_ACCEPTED Policy rejects transited path'
	krb_err_response_too_big:              'KRB_ERR_RESPONSE_TOO_BIG Response too big for UDP; retry with TCP'
	krb_err_generic:                       'KRB_ERR_GENERIC Generic error (description in e-text)'
	krb_err_field_toolong:                 'KRB_ERR_FIELD_TOOLONG Field is too long for this implementation'
	kdc_error_client_not_trusted:          'KDC_ERROR_CLIENT_NOT_TRUSTED Reserved for PKINIT'
	kdc_error_kdc_not_trusted:             'KDC_ERROR_KDC_NOT_TRUSTED Reserved for PKINIT'
	kdc_error_invalid_sig:                 'KDC_ERROR_INVALID_SIG Reserved for PKINIT'
	kdc_err_key_too_weak:                  'KDC_ERR_KEY_TOO_WEAK Reserved for PKINIT'
	kdc_err_certificate_mismatch:          'KDC_ERR_CERTIFICATE_MISMATCH Reserved for PKINIT'
	krb_ap_err_no_tgt:                     'KRB_AP_ERR_NO_TGT No TGT available to validate USER-TO-USER'
	kdc_err_wrong_realm:                   'KDC_ERR_WRONG_REALM Reserved for future use'
	krb_ap_err_user_to_user_required:      'KRB_AP_ERR_USER_TO_USER_REQUIRED Ticket must be for USER-TO-USER'
	kdc_err_cant_verify_certificate:       'KDC_ERR_CANT_VERIFY_CERTIFICATE Reserved for PKINIT'
	kdc_err_invalid_certificate:           'KDC_ERR_INVALID_CERTIFICATE Reserved for PKINIT'
	kdc_err_revoked_certificate:           'KDC_ERR_REVOKED_CERTIFICATE Reserved for PKINIT'
	kdc_err_revocation_status_unknown:     'KDC_ERR_REVOCATION_STATUS_UNKNOWN Reserved for PKINIT'
	kdc_err_revocation_status_unavailable: 'KDC_ERR_REVOCATION_STATUS_UNAVAILABLE Reserved for PKINIT'
	kdc_err_client_name_mismatch:          'KDC_ERR_CLIENT_NAME_MISMATCH Reserved for PKINIT'
	kdc_err_kdc_name_mismatch:             'KDC_ERR_KDC_NAME_MISMATCH Reserved for PKINIT'
}

pub fn (k KrbError) msg() string {
	value := messages.error_code_by_id[k.error_code] or { return 'UNKNOW KDC ERROR' }
	return value
}

pub fn (k KrbError) code() int {
	return k.error_code
}
