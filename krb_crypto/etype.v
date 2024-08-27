module krb_crypto

// reserved : 0
const des_cbc_crc = int(1)
const des_cbc_md4 = int(2)
const des_cbc_md5 = int(3)
const des_cbc_raw = int(4)
const des3_cbc_md5 = int(5)
const des3_cbc_raw = int(6)
const des3_cbc_sha1 = int(7)
const des_hmac_sha1 = int(8)
const dsawithsha1_cmsoid = int(9)
const md5withrsaencryption_cmsoid = int(10)
const sha1withrsaencryption_cmsoid = int(11)
const rc2cbc_envoid = int(12)
const rsaencryption_envoid = int(13)
const rsaes_oaep_env_oid = int(14)
const des_ede3_cbc_env_oid = int(15)
const des3_cbc_sha1_kd = int(16)
const aes128_cts_hmac_sha1_96 = int(17)
const aes256_cts_hmac_sha1_96 = int(18)
const aes128_cts_hmac_sha256_128 = int(19)
const aes256_cts_hmac_sha384_192 = int(20)
// unassigned : 21-22
pub const rc4_hmac = int(23)
const rc4_hmac_exp = int(24)
const camellia128_cts_cmac = int(25)
const camellia256_cts_cmac = int(26)
// unassigned : 27-64
const subkey_keymaterial = int(65) // unassigned : 66-2147483647


//reserved : 0
const crc32         = int(1)
const rsa_md4       = int(2)
const rsa_md4_des   = int(3)
const des_mac       = int(4)
const des_mac_k     = int(5)
const rsa_md4_des_k = int(6)
const rsa_md5       = int(7)
const rsa_md5_des   = int(8)
const rsa_md5_des3  = int(9)
const sha1_id10     = int(10)
//unassigned : 11
const hmac_sha1_des3_kd      = int(12)
const hmac_sha1_des3         = int(13)
const sha1_id14              = int(14)
const hmac_sha1_96_aes128    = int(15)
const hmac_sha1_96_aes256    = int(16)
const cmac_camellia128       = int(17)
const cmac_camellia256       = int(18)
const hmac_sha256_128_aes128 = int(19)
const hmac_sha384_192_aes256 = int(20)
//unassigned : 21-32770
const gssapi = int(32771)
//unassigned : 32772-2147483647
const kerb_checksum_hmac_md5_unsigned = u32(4294967158) // 0xffffff76 documentation says this is -138 but in an unsigned int this is 4294967158
const kerb_checksum_hmac_md5          = int(-138)

interface Etype {
	get_etype_id() int
	get_hash_id() int
	get_key_byte_size() int
	get_default_string_to_key_params() string
	string_to_key(passwd string, salt string, sk2params string) ![]u8
	do_encrypt_data(key []u8, data []u8) ![]u8
	do_decrypt_data(key []u8, data []u8) ![]u8
	encrypt_message(key []u8, data []u8, usage u32) ![]u8
	decrypt_message(key []u8, data []u8, usage u32) ![]u8
	checksum(key []u8, data []u8, usage u32) ![]u8

}

pub fn get_etype(id int) !Etype {
	e := match id {
		krb_crypto.rc4_hmac { RC4HMAC{} }
		else { return error('unknown or unsupported Etype ${id}') }
	}

	return e
}
