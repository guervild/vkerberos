module types

import asn1
import time

import constants

pub struct Authenticator {
pub mut:	
	avno int
	crealm string
	cname             PrincipalName     
	cksum             Checksum          
	cusec             int               
	ctime             time.Time         
	subkey            EncryptionKey     //OPTIONAL
	seqnumber         i64             
	//AuthorizationData AuthorizationData //OPTIONAL 
}

pub fn Authenticator.new(crealm string, cname PrincipalName) Authenticator {
	
	now := time.now().local_to_utc()

	return Authenticator{
		avno: constants.pvno
		crealm: crealm
		cname: cname
		cksum: Checksum{}	
		cusec: int((now.unix_nano() / i64(time.microsecond)) - (now.unix() * i64(1000000)))
		ctime: now
	}
}

pub fn (a Authenticator) asn1() !asn1.Encoder {

	mut seq := asn1.new_sequence()

	seq.add(asn1.new_explicit_context(asn1.new_integer(a.avno), 0))
	seq.add(asn1.new_explicit_context(asn1.new_generalstring(a.crealm)!, 1))
	seq.add(asn1.new_explicit_context(a.cname.asn1(), 2))

	if a.cksum != Checksum{} {
		seq.add(asn1.new_explicit_context(a.cksum.asn1(), 3))
	}

	seq.add(asn1.new_explicit_context(asn1.new_integer(int(a.cusec)), 4))

	seq.add(asn1.new_explicit_context(types.to_kerberos_time(a.ctime)!, 5))

	if a.subkey != EncryptionKey{} {
		seq.add(asn1.new_explicit_context(a.subkey.asn1(), 6))
	}

	//TODO: SEQNUMB ET AUTHDATA
	//TODO: application to constants

	asn1_obj := asn1.new_asn_object(.application, true, 2, seq.encode()!)

	return asn1_obj
}


pub fn (a Authenticator) pack() ![]u8 {
	b := a.asn1()!
	
	return b.encode()!
}

pub fn (a Authenticator) encrypt(key EncryptionKey, usage u32, kvno int) !EncryptedData {

	b := a.pack()!

	return EncryptedData.new_encrypted_data(b, key, usage, kvno)
}