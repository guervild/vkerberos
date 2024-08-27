module krb_crypto

import crypto.hmac
import crypto.md5
import crypto.rc4
import crypto.rand
import encoding.binary
import encoding.hex
import v_crypto.md4

pub struct RC4HMAC {
}

pub fn (e RC4HMAC) get_etype_id() int {
	return rc4_hmac
}

pub fn (e RC4HMAC) get_hash_id() int {
	return kerb_checksum_hmac_md5
}

pub fn (e RC4HMAC) get_key_byte_size() int {
	return 16
}

pub fn (e RC4HMAC) get_default_string_to_key_params() string {
	return ''
}

pub fn (e RC4HMAC) do_hmac(key []u8, data []u8) []u8 {
	mac := hmac.new(key, data, md5.sum, md5.block_size)

	return mac
}

pub fn (e RC4HMAC) usage_to_msg_type(usage u32) []u8 {
	mut new_usage := usage

	if usage == 3 {
		new_usage = 8
	// } else if usage == 9 {
	// 	new_usage = 8
	} else if usage == 23 {
		new_usage = 13
	}

	mut tb := []u8{len: 4, init: 0}
	binary.little_endian_put_u64(mut tb, u64(new_usage))
	return tb
}

pub fn (e RC4HMAC) do_encrypt_data(key []u8, data []u8) ![]u8 {
	if key.len != e.get_key_byte_size() {
		return error('incorrect keysize: expected ${e.get_key_byte_size()} actual ${key.len}')
	}

	mut cipher := rc4.new_cipher(key) or { return error('error creating rc4 cipher: ${err}') }

	mut ed := data.clone()

	cipher.xor_key_stream(mut ed, ed)
	cipher.reset()

	return ed
}

pub fn (e RC4HMAC) do_decrypt_data(key []u8, data []u8) ![]u8 {
	return e.do_encrypt_data(key, data)!
}

pub fn (e RC4HMAC) encrypt_message(key []u8, data []u8, usage u32) ![]u8 {
	mut confounder := rand.read(8)!

	k1 := key.clone()
	k2 := e.do_hmac(k1, e.usage_to_msg_type(usage))

	mut toenc := confounder.clone()
	toenc << data

	chksum := e.do_hmac(k2, toenc)
	mut k3 := e.do_hmac(k2, chksum)

	encrypted := e.do_encrypt_data(k3, toenc)!

	mut msg := chksum.clone()
	println("msg:")
	println(msg)
	println("encrypted:")
	println(encrypted)
	msg << encrypted

	return msg
}

pub fn (e RC4HMAC) decrypt_message(key []u8, data []u8, usage u32) ![]u8 {
	if data.len < 24 {
		return error('cipher text is too short')
	}

	cksum := data[..16]
	cipher_text := data[16..]

	ki := e.do_hmac(key, e.usage_to_msg_type(usage))

	ke := e.do_hmac(ki, cksum)

	plaintext := e.do_decrypt_data(ke, cipher_text)!

	return plaintext[8..]
}

pub fn (e RC4HMAC) string_to_key(secret string, salt string, sk2params string) ![]u8 {
	mut b := []u8{len: secret.len * 2, init: 0}
	// println('bef string to')

	for i, r in secret {
		u := '${r:04x}'
		u_bytes := hex.decode(u)!
		b[2 * i] = u_bytes[1]
		b[2 * i + 1] = u_bytes[0]
	}

	mut d := md4.new()
	_, bytes_hash := d.checksum(b)
	d.reset()

	// println('before sending hash')
	return bytes_hash
}

pub fn (e RC4HMAC) checksum(key []u8, data []u8, usage u32) ![]u8 {

	mut s := 'signaturekey\x00'.bytes()
	println(s)
	println("OOOOOOOOOOOOOOOOOOOOOOOoo")
	//s << [u8(0x0), 0x0]


	mc := e.do_hmac(key, s)

	tb := e.usage_to_msg_type(u32(usage))

	mut p := tb.clone()
	p << data

	//md5 sum
	mut m5 := md5.new()
	m5.write(p)!

	mut sum := m5.sum([])

	return  e.do_hmac(mc, sum)
}