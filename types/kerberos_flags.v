module types

// TODO: Create a type

pub fn set_kdc_options(mut arr []u8, flag int) {
	// Get the index of the uint32 element in the array
	i := flag / 8

	// Get the bit position within the uint32 element
	p := u32(7 - (flag - 8 * i))

	// Set the bit in the uint32 element
	arr[i] |= 1 << p
}
