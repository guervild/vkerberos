module nametype

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.8
pub const krb_nt_unknown = int(0)

// Name type not known
pub const krb_nt_principal = int(1)

// Just the name of the principal as in DCE,  or for users
pub const krb_nt_srv_inst = int(2)

// Service and other unique instance (krbtgt)
pub const krb_nt_srv_hst = int(3)

// Service with host name as instance (telnet, rcommands)
pub const krb_nt_srv_xhst = int(4)

// Service with host as remaining components
pub const krb_nt_uid = int(5)

// Unique ID
pub const krb_nt_x500_principal = int(6)

// Encoded X.509 Distinguished name [RFC2253]
pub const krb_nt_smtp_name = int(7)

// Name in form of SMTP email name (e.g., user@example.com)
pub const krb_nt_enterprise = int(10)

// Enterprise name; may be mapped to principal name
pub const krb_nt_ms_principal = int(-128)
pub const krb_nt_ms_principal_and_id = int(-129)
pub const krb_nt_ent_principal_and_id = int(-130)
