module types

import time
import asn1

pub fn to_kerberos_time(t time.Time) !asn1.Encoder {
	t_formated := t.custom_format('YYYYMMDDHHmmss')
	return asn1.new_generalizedtime('${t_formated}Z')!
}

pub fn from_keberos_time(to_parse string) !time.Time {
	t := time.parse_format(to_parse, 'YYYYMMDDHHmmssZ')!
	return t
}
