module messages

import encoding.hex
import time
import types {EncryptedData, PrincipalName, HostAddress }
import constants.nametype

fn test_pack_kdc_req_body_generic() ! {
	// test fail because host addresses on 4 bytes in the provided data, and 8 in the packed one
	data := hex.decode('308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765')!
	
	p_name := PrincipalName{
		name_type: nametype.krb_nt_principal
			name_string: ['hftsai', 'extra']
		}
	
	b := KDCReqBody {
		kdc_options: '0b11111110110111001011101010010000'.u8_array()
		cname: p_name
		realm: 'ATHENA.MIT.EDU'
		sname: p_name
		from: time.parse("1994-06-10 06:03:17")!
		till: time.parse("1994-06-10 06:03:17")!
		rtime: time.parse("1994-06-10 06:03:17")!
		nonce: 42
		etype: [0, 1]
		addresses: [
			HostAddress{
				addr_type: 2
				address: '12D00023'
			},
			HostAddress{
				addr_type: 2
				address: '12D00023'
			},	
		]
		encauthdata: EncryptedData{
			etype: 0
			kvno: 5
			cipher: 'krbASN.1 test message'.bytes()
		}
		additionnal_tickets: [
			Ticket{
				tkt_vno: 5
				realm: 'ATHENA.MIT.EDU'
				sname: types.PrincipalName{
					name_type: 1
					name_string: ['hftsai', 'extra']
				}
				enc_part: types.EncryptedData{
					etype: 0
					kvno: 5
					cipher: 'krbASN.1 test message'.bytes()
				}
			},
			Ticket{
				tkt_vno: 5
				realm: 'ATHENA.MIT.EDU'
				sname: types.PrincipalName{
					name_type: 1
					name_string: ['hftsai', 'extra']
				}
				enc_part: types.EncryptedData{
					etype: 0
					kvno: 5
					cipher: 'krbASN.1 test message'.bytes()
				}
			}	
		]
	}
	
	assert data == b.pack()!
}