module msgtype

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.7
// https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/ds/security/protocols/kerberos/inc/kerbcomm.h#L63
pub const krb_as_req = int(10)
// Request for initial authentication
pub const krb_as_rep = int(11)
// Response to KRB_AS_REQ request
pub const krb_tgs_req = int(12)
// Request for authentication based on TGT
pub const krb_tgs_rep = int(13)
// Response to KRB_TGS_REQ request
pub const krb_ap_req = int(14)
// Application request to server
pub const krb_ap_rep = int(15)
// Response to KRB_AP_REQ_MUTUAL
pub const krb_reserved16 = int(16)
// Reserved for user-to-user krb_tgt_request
pub const krb_reserved17 = int(17)
// Reserved for user-to-user krb_tgt_reply
pub const krb_safe = int(20)
// Safe (checksummed) application message
pub const krb_priv = int(21)
// Private (encrypted) application message
pub const krb_cred = int(22)
// Private (encrypted) message to forward credentials
pub const krb_error = int(30)
// Error response
