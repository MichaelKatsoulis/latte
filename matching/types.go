package matching

type Match struct {
	InMsg    uint8
	OutMsg   uint8
	InMatch  func([]byte) []byte
	OutMatch func([]byte) []byte
}
