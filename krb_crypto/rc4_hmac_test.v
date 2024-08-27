module krb_crypto

import v_crypto.md4

const test_password = 'foo'
const test_key = 'ac8e657f83df82beea5d43bdaf7800cc'

fn test_rc4_hmac() ! {
	r := RC4HMAC{}
	checksum_key := r.string_to_key(krb_crypto.test_password, '', '')!.hex()

	assert checksum_key == krb_crypto.test_key
}
