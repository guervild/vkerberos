module network

import net
import io
import encoding.binary
import time

pub fn send_bytes(ip_address string, port int, mut data []u8) ![]u8 {
	mut conn := net.dial_tcp('${ip_address}:${port}') or { panic(err) }

	conn.set_write_timeout(1 * time.second)
	conn.set_read_timeout(1 * time.second)

	defer {
		conn.close() or { panic(err) }
	}

	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	mut size_send := []u8{len: 4, init: 0}
	binary.big_endian_put_u32(mut size_send, u32(data.len))

	// TODO
	// mut to_send := []u8{}
	// to_send << size_send
	// to_send << data

	conn.write(size_send) or { panic('error while sending size: ${err}') }
	conn.write(data) or { panic('error while sending data: ${err}') }

	mut size_rcv := []u8{len: 4, init: 0}

	result := conn.read(mut &size_rcv) or { panic('error while reading size received ${err}') }
	size_rcv_int := u32(binary.big_endian_u32(size_rcv))

	if size_rcv_int < 1 {
		return error('error receive no response data from kdc')
	}

	res := io.read_all(reader: conn)!

	if res.len != size_rcv_int {
		return error('error receive a incomplete message from kdc')
	}

	return res
}
