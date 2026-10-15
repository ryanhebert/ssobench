package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
)

// decodeCBOR reads one CBOR item from b and returns it with the bytes after
// it. It covers what WebAuthn uses: integers (as int64), byte and text
// strings, arrays, maps, booleans, null and floats. Indefinite lengths and
// tags are refused; authenticators do not send them.
func decodeCBOR(b []byte) (any, []byte, error) {
	return decodeItem(b, 0)
}

var errCBOR = errors.New("malformed CBOR")

func decodeItem(b []byte, depth int) (any, []byte, error) {
	if depth > 16 || len(b) == 0 {
		return nil, nil, errCBOR
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	if major == 7 {
		switch info {
		case 20:
			return false, b, nil
		case 21:
			return true, b, nil
		case 22, 23:
			return nil, b, nil
		case 25:
			if len(b) < 2 {
				return nil, nil, errCBOR
			}
			return float64(binary.BigEndian.Uint16(b)), b[2:], nil // half floats: value is not needed
		case 26:
			if len(b) < 4 {
				return nil, nil, errCBOR
			}
			return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), b[4:], nil
		case 27:
			if len(b) < 8 {
				return nil, nil, errCBOR
			}
			return math.Float64frombits(binary.BigEndian.Uint64(b)), b[8:], nil
		}
		return nil, nil, errCBOR
	}
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info == 24 && len(b) >= 1:
		n, b = uint64(b[0]), b[1:]
	case info == 25 && len(b) >= 2:
		n, b = uint64(binary.BigEndian.Uint16(b)), b[2:]
	case info == 26 && len(b) >= 4:
		n, b = uint64(binary.BigEndian.Uint32(b)), b[4:]
	case info == 27 && len(b) >= 8:
		n, b = binary.BigEndian.Uint64(b), b[8:]
	default:
		return nil, nil, errCBOR
	}
	switch major {
	case 0:
		if n > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return int64(n), b, nil
	case 1:
		if n > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return -1 - int64(n), b, nil
	case 2, 3:
		if n > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		if major == 3 {
			return string(b[:n]), b[n:], nil
		}
		return append([]byte(nil), b[:n]...), b[n:], nil
	case 4:
		if n > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		out := make([]any, 0, n)
		for range n {
			var v any
			var err error
			if v, b, err = decodeItem(b, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, b, nil
	case 5:
		if n > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		out := make(map[any]any, n)
		for range n {
			var k, v any
			var err error
			if k, b, err = decodeItem(b, depth+1); err != nil {
				return nil, nil, err
			}
			if v, b, err = decodeItem(b, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, errCBOR
			}
			out[k] = v
		}
		return out, b, nil
	}
	return nil, nil, errCBOR // major 6: tags
}
