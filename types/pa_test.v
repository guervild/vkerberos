module types

import encoding.hex
import asn1
import constants.patype

fn test_pack_pa_pac_request() ! {
	data := [u8(0x30), 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09, 0x04, 0x07, 0x30,
		0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]
	pa_data := PAData.new_kerb_pa_pac_request(true)!

	pa_data_packed := pa_data.pack()!

	assert pa_data_packed == data
}

fn test_unpack_sequence_of_padata() ! {

	data := hex.decode('30243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461')!
	out := asn1.der_decode(data)!

	padata_seq := out.as_sequence()!

	mut padata_arr := []PAData{}

	for curr_padata in padata_seq.elements() {
		mut pa := PAData.from_bytes(curr_padata.encode()!)!

		padata_arr << pa
	}

	assert padata_arr.len == 2
	assert padata_arr[0].pa_data_type == patype.pa_sam_response
	assert padata_arr[0].pa_data_value.bytestr() == "pa-data"
}

fn test_pack_sequenceof_padata() ! {
	data := hex.decode('30243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461')!

	mut pas := [
		PAData{
			pa_data_type: 13
			pa_data_value: "pa-data".bytes()
		},
		PAData{
			pa_data_type: 13
			pa_data_value: "pa-data".bytes()
		}
	]

	mut seq_pas := asn1.new_sequence()

	for p in pas {
		seq_pas.add(p.asn1())
	}

	assert seq_pas.encode()! == data
}

fn test_unpack_edata() ! {
	data := hex.decode('3051301EA003020100A10D1B0B4D6F72746F6E2773202330A208040673326B3A2030300FA003020101A208040673326B3A2031301EA003020102A10D1B0B4D6F72746F6E2773202332A208040673326B3A2032')!
	e := EtypeInfo2.from_bytes(data)!

	assert e.len == 3
	assert e[0].etype == 0
	assert e[0].salt == 'Morton\'s #0'
	assert e[1].etype == 1
	assert e[1].salt == ''
}
