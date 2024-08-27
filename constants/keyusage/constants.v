module keyusage

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.1

// key usage numbers.
pub const as_req_pa_enc_timestamp = int(1)
pub const kdc_rep_ticket = int(2)
pub const as_rep_encpart = int(3)
pub const tgs_req_kdc_req_body_authdata_session_key = int(4)
pub const tgs_req_kdc_req_body_authdata_sub_key = int(5)
pub const tgs_req_pa_tgs_req_ap_req_authenticator_chksum = int(6)
pub const tgs_req_pa_tgs_req_ap_req_authenticator = int(7)
pub const tgs_rep_encpart_session_key = int(8)
pub const tgs_rep_encpart_authenticator_sub_key = int(9)
pub const ap_req_authenticator_chksum = int(10)
pub const ap_req_authenticator = int(11)
pub const ap_rep_encpart = int(12)
pub const krb_priv_encpart = int(13)
pub const krb_cred_encpart = int(14)
pub const krb_safe_chksum = int(15)
pub const kerb_non_kerb_salt = int(16)
pub const kerb_non_kerb_cksum_salt = int(17)

// 18.  reserved for future use in kerberos and related protocols.
pub const ad_kdc_issued_chksum = int(19)

// 20-21.  reserved for future use in kerberos and related protocols.
pub const gssapi_acceptor_seal = int(22)
pub const gssapi_acceptor_sign = int(23)
pub const gssapi_initiator_seal = int(24)
pub const gssapi_initiator_sign = int(25)
pub const key_usage_fast_req_chksum = int(50)
pub const key_usage_fast_enc = int(51)
pub const key_usage_fast_rep = int(52)
pub const key_usage_fast_finished = int(53)
pub const key_usage_enc_challenge_client = int(54)
pub const key_usage_enc_challenge_kdc = int(55)
pub const key_usage_as_req = int(56) // 26-511.  reserved for future use in kerberos and related protocols.
// 512-1023.  reserved for uses internal to a kerberos implementation.
// 1024.  encryption for application use in protocols that do not specify key usage values
// 1025.  checksums for application use in protocols that do not specify key usage values
// 1026-2047.  reserved for application use.
