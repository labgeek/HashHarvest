package readers

// PDF standard security handler (ISO 32000-2 §7.6.4), enough to open what
// pypdf opens without a password: documents whose user password is empty
// (or whose owner password is empty), encrypted with RC4 (revisions 2-4),
// AES-128 (revision 4) or AES-256 (revisions 5 and 6).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

var pdfPadding = []byte("\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08" +
	"\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A")

var errPDFPassword = errors.New("encrypted PDF requires a password")

type pdfCrypt struct {
	key      []byte
	aes      bool // AES-CBC rather than RC4
	v5       bool // AES-256: the file key is used as is, not per object
	identity bool // streams are stored unencrypted (/StmF /Identity)
}

// encryption returns the newest trailer's /Encrypt dictionary and the first
// /ID string, or nil when the document is not encrypted.
func (d *pdfDoc) encryption() (pdfDict, []byte, error) {
	var enc pdfDict
	var id []byte
	found := false
	for i := len(d.trailers) - 1; i >= 0; i-- {
		t := d.trailers[i]
		if !found && t["Encrypt"] != nil {
			found = true
			enc, _ = d.dict(t["Encrypt"])
		}
		if ids := d.array(t["ID"]); id == nil && len(ids) > 0 {
			id, _ = d.resolve(ids[0]).([]byte)
		}
	}
	if found && enc == nil {
		return nil, nil, errors.New("damaged PDF encryption dictionary")
	}
	return enc, id, nil
}

func (d *pdfDoc) newCrypt(enc pdfDict, id []byte) (*pdfCrypt, error) {
	if f := d.name(enc["Filter"]); f != "Standard" {
		return nil, fmt.Errorf("unsupported PDF security handler %q", f)
	}
	v, r := int(d.num(enc["V"])), int(d.num(enc["R"]))
	str := func(key string) []byte { b, _ := d.resolve(enc[key]).([]byte); return b }
	o, u := str("O"), str("U")
	c := &pdfCrypt{}

	length := 5
	if v >= 4 {
		length = 16
	}
	if n := int(d.num(enc["Length"])); v > 1 && n >= 40 && n <= 128 && n%8 == 0 {
		length = n / 8
	}
	if v >= 4 {
		method := "Identity"
		if stmf := d.name(enc["StmF"]); stmf != "" && stmf != "Identity" {
			cfs, _ := d.dict(enc["CF"])
			cf, _ := d.dict(cfs[stmf])
			method = d.name(cf["CFM"])
		}
		switch method {
		case "Identity", "None":
			c.identity = true
		case "V2":
		case "AESV2", "AESV3":
			c.aes = true
		default:
			return nil, fmt.Errorf("unsupported PDF crypt filter %q", method)
		}
	}

	switch r {
	case 2, 3, 4:
		if len(o) < 32 || len(u) < 32 {
			return nil, errors.New("damaged PDF encryption dictionary")
		}
		o, u = o[:32], u[:32]
		var perms [4]byte
		// /P is written signed (-4) or unsigned (4294967292); both are the same 32 bits.
		binary.LittleEndian.PutUint32(perms[:], uint32(int64(d.num(enc["P"]))))
		encryptMeta := true
		if b, ok := d.resolve(enc["EncryptMetadata"]).(bool); ok {
			encryptMeta = b
		}
		fileKey := func(password []byte) []byte { // Algorithm 2
			h := md5.New()
			h.Write(pdfPad(password))
			h.Write(o)
			h.Write(perms[:])
			h.Write(id)
			if r >= 4 && !encryptMeta {
				h.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
			}
			k := h.Sum(nil)
			if r >= 3 {
				for i := 0; i < 50; i++ {
					s := md5.Sum(k[:length])
					k = s[:]
				}
			}
			return k[:length]
		}
		userOK := func(key []byte) bool { // Algorithms 4 and 5
			if r == 2 {
				return bytes.Equal(rc4XOR(key, pdfPadding), u)
			}
			s := md5.Sum(append(append([]byte(nil), pdfPadding...), id...))
			x := s[:]
			for i := 0; i < 20; i++ {
				x = rc4XOR(xorKey(key, byte(i)), x)
			}
			return bytes.Equal(x, u[:16])
		}
		if k := fileKey(nil); userOK(k) {
			c.key = k
			break
		}
		// The empty string as the owner password (Algorithm 7).
		s := md5.Sum(pdfPadding)
		ownerKey := s[:]
		if r >= 3 {
			for i := 0; i < 50; i++ {
				s = md5.Sum(ownerKey)
				ownerKey = s[:]
			}
		}
		ownerKey = ownerKey[:length]
		userPassword := rc4XOR(ownerKey, o)
		if r >= 3 {
			userPassword = o
			for i := 19; i >= 0; i-- {
				userPassword = rc4XOR(xorKey(ownerKey, byte(i)), userPassword)
			}
		}
		if k := fileKey(userPassword); userOK(k) {
			c.key = k
			break
		}
		return nil, errPDFPassword
	case 5, 6:
		ue, oe := str("UE"), str("OE")
		if len(o) < 48 || len(u) < 48 || len(ue) < 32 || len(oe) < 32 {
			return nil, errors.New("damaged PDF encryption dictionary")
		}
		hash := func(salt, udata []byte) []byte {
			if r == 5 {
				s := sha256.Sum256(append(append([]byte(nil), salt...), udata...))
				return s[:]
			}
			return pdfHashR6(salt, udata)
		}
		var wrapped, kek []byte
		switch {
		case bytes.Equal(hash(u[32:40], nil), u[:32]):
			wrapped, kek = ue[:32], hash(u[40:48], nil)
		case bytes.Equal(hash(o[32:40], u[:48]), o[:32]):
			wrapped, kek = oe[:32], hash(o[40:48], u[:48])
		default:
			return nil, errPDFPassword
		}
		block, _ := aes.NewCipher(kek)
		c.key = make([]byte, 32)
		cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(c.key, wrapped)
		c.v5 = true
	default:
		return nil, fmt.Errorf("unsupported PDF encryption revision %d", r)
	}
	return c, nil
}

// pdfHashR6 is Algorithm 2.B for an empty password.
func pdfHashR6(salt, udata []byte) []byte {
	s := sha256.Sum256(append(append([]byte(nil), salt...), udata...))
	k := s[:]
	for round := 1; ; round++ {
		k1 := bytes.Repeat(append(append([]byte(nil), k...), udata...), 64)
		block, _ := aes.NewCipher(k[:16])
		e := make([]byte, len(k1))
		cipher.NewCBCEncrypter(block, k[16:32]).CryptBlocks(e, k1)
		sum := 0
		for _, b := range e[:16] {
			sum += int(b)
		}
		switch sum % 3 { // the first 16 bytes as a big-endian number, mod 3
		case 0:
			h := sha256.Sum256(e)
			k = h[:]
		case 1:
			h := sha512.Sum384(e)
			k = h[:]
		default:
			h := sha512.Sum512(e)
			k = h[:]
		}
		if round >= 64 && int(e[len(e)-1]) <= round-32 {
			return k[:32]
		}
	}
}

// decrypt decrypts the data of object num/gen (Algorithm 1).
func (c *pdfCrypt) decrypt(num, gen int, data []byte) ([]byte, error) {
	if c.identity {
		return data, nil
	}
	key := c.key
	if !c.v5 {
		h := md5.New()
		h.Write(c.key)
		h.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), byte(gen), byte(gen >> 8)})
		if c.aes {
			h.Write([]byte("sAlT"))
		}
		key = h.Sum(nil)
		if n := len(c.key) + 5; n < 16 {
			key = key[:n]
		}
	}
	if !c.aes {
		return rc4XOR(key, data), nil
	}
	if len(data) < 16 || len(data)%16 != 0 {
		return nil, errors.New("damaged AES-encrypted PDF stream")
	}
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(data)-16)
	cipher.NewCBCDecrypter(block, data[:16]).CryptBlocks(out, data[16:])
	if n := len(out); n > 0 && int(out[n-1]) >= 1 && int(out[n-1]) <= 16 && int(out[n-1]) <= n {
		out = out[:n-int(out[n-1])] // PKCS#5 padding
	}
	return out, nil
}

func pdfPad(password []byte) []byte {
	if len(password) > 32 {
		password = password[:32]
	}
	return append(append([]byte(nil), password...), pdfPadding[:32-len(password)]...)
}

func rc4XOR(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

func xorKey(key []byte, b byte) []byte {
	out := make([]byte, len(key))
	for i := range key {
		out[i] = key[i] ^ b
	}
	return out
}
