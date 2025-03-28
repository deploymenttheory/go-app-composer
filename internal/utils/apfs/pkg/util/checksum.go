// File: pkg/util/checksum.go
package util

// Fletcher64 computes the Fletcher64 checksum used in APFS object headers.
// This function processes the buffer as a sequence of uint32s.
func Fletcher64(data []byte) uint64 {
	var sum1 uint64 = 0
	var sum2 uint64 = 0
	n := len(data) / 4
	for i := 0; i < n; i++ {
		word := uint64(uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24)
		sum1 = (sum1 + word) % 0xffffffff
		sum2 = (sum2 + sum1) % 0xffffffff
	}

	return (sum2 << 32) | sum1
}

// ValidateFletcher64 compares the stored checksum against the computed checksum of a buffer
func ValidateFletcher64(data []byte, expected uint64) bool {
	return Fletcher64(data) == expected
}

// Fletcher64WithZeroedChecksum calculates the Fletcher64 checksum with checksum field zeroed
func Fletcher64WithZeroedChecksum(data []byte, cksumOffset int) uint64 {
	tmp := make([]byte, len(data))
	copy(tmp, data)
	if cksumOffset+8 > len(tmp) {
		return 0
	}
	for i := 0; i < 8; i++ {
		tmp[cksumOffset+i] = 0
	}
	return Fletcher64(tmp)
}
