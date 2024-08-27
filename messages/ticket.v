module messages

import time
import asn1
import types { EncryptedData, EncryptionKey, HostAddresses, PrincipalName }

pub const application_ticket_type = int(1)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.3
pub struct Ticket {
pub mut:
	tkt_vno            int
	realm              string
	sname              PrincipalName
	enc_part           EncryptedData
	decrypted_enc_part EncTicketPart
}

struct EncTicketPart {
	flags      []u8
	key        EncryptionKey
	crealm     string
	cname      PrincipalName
	transited  TransiterEncoding
	auth_time  time.Time
	start_time time.Time
	end_time   time.Time
	renew_time time.Time
	c_addr     HostAddresses
	// authorization_data AuthorizationData
}

struct TransiterEncoding {
	tr_type  int
	contents []u8
}

pub fn Ticket.from_bytes(data []u8) !Ticket {
	mut t := Ticket{}

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
			t.tkt_vno = n as int
		}

		if curr_number == 1 {
			s := curr_tagged.as_inner().as_generalstring()!
			t.realm = string(s)
		}

		if curr_number == 2 {
			s := curr_tagged.as_inner().as_sequence()!
			pn := PrincipalName.from_bytes(s.encode()!)!
			t.sname = pn
		}

		if curr_number == 3 {
			in_seq := curr_tagged.as_inner().as_sequence()!
			t.enc_part = EncryptedData.from_asn1_sequence(in_seq)!
		}
	}

	return t
}

fn (t Ticket) asn1() !asn1.Encoder {
	mut seq := asn1.new_sequence()
	seq.add(asn1.new_explicit_context(asn1.new_integer(t.tkt_vno), 0))
	seq.add(asn1.new_explicit_context(asn1.new_generalstring(t.realm)!, 1))
	seq.add(asn1.new_explicit_context(t.sname.asn1(), 2))
	seq.add(asn1.new_explicit_context(t.enc_part.asn1(), 3))

	ticket_asn1 := asn1.new_asn_object(.application, true, messages.application_ticket_type,
		seq.encode()!)

	return ticket_asn1
}
