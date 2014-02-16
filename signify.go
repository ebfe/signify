package signify

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/agl/ed25519"
	"github.com/ebfe/bcrypt_pbkdf"
)

const (
	commentHdr = "untrusted comment: "
)

var (
	algoEd     = []byte{'E', 'd'}
	algoBcrypt = []byte{'B', 'K'}
)

type PrivateKey struct {
	Bytes       [ed25519.PrivateKeySize]byte
	Fingerprint [8]byte
}

type PublicKey struct {
	Bytes       [ed25519.PublicKeySize]byte
	Fingerprint [8]byte
}

type Signature struct {
	Bytes       [ed25519.SignatureSize]byte
	Fingerprint [8]byte
}

type rawEncryptedKey struct {
	PKAlgo       [2]byte
	KDFAlgo      [2]byte
	KDFRounds    uint32
	Salt         [16]byte
	Checksum     [8]byte
	Fingerprint  [8]byte
	EncryptedKey [ed25519.PrivateKeySize]byte
}

type rawPublicKey struct {
	PKAlgo      [2]byte
	Fingerprint [8]byte
	PublicKey   [ed25519.PublicKeySize]byte
}

type rawSignature struct {
	PKAlgo      [2]byte
	Fingerprint [8]byte
	Signature   [ed25519.SignatureSize]byte
}

func ReadFile(r io.Reader) (comment string, content []byte, err error) {
	sc := bufio.NewScanner(r)

	if !sc.Scan() {
		return "", nil, fmt.Errorf("signify: read error %s", sc.Err())
	}
	comment = sc.Text()
	if !strings.HasPrefix(comment, commentHdr) {
		return "", nil, errors.New("signify: missing header")
	}
	comment = comment[len(commentHdr):]

	if !sc.Scan() {
		return "", nil, fmt.Errorf("signify: read error %s", sc.Err())
	}
	content, err = base64.StdEncoding.DecodeString(sc.Text())

	return
}

func WriteFile(w io.Writer, comment string, content []byte) error {
	b64 := base64.StdEncoding.EncodeToString(content)
	_, err := fmt.Fprintf(w, "%s%s\n%s\n", commentHdr, comment, b64)
	return err
}

func parseRawEncryptedKey(data []byte) (*rawEncryptedKey, error) {
	var ek rawEncryptedKey
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &ek); err != nil {
		return nil, err
	}
	return &ek, nil
}

func parseRawPublicKey(data []byte) (*rawPublicKey, error) {
	var pub rawPublicKey
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &pub); err != nil {
		return nil, err
	}
	return &pub, nil
}

func parseRawSignature(data []byte) (*rawSignature, error) {
	var sig rawSignature
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

func decryptPrivateKey(rek *rawEncryptedKey, passphrase []byte) (*PrivateKey, error) {
	var priv PrivateKey
	var xorkey []byte

	if rek.KDFRounds > 0 {
		xorkey = bcrypt_pbkdf.Key(passphrase, rek.Salt[:], int(rek.KDFRounds), ed25519.PrivateKeySize)
	} else {
		xorkey = make([]byte, ed25519.PrivateKeySize)
	}

	for i := range priv.Bytes {
		priv.Bytes[i] = rek.EncryptedKey[i] ^ xorkey[i]
	}

	sha := sha512.New()
	sha.Write(priv.Bytes[:])
	checksum := sha.Sum(nil)

	if subtle.ConstantTimeCompare(checksum[:len(rek.Checksum)], rek.Checksum[:]) != 1 {
		return nil, errors.New("signify: invalid passphrase")
	}

	priv.Fingerprint = rek.Fingerprint

	return &priv, nil
}

func ParsePrivateKey(data, passphrase []byte) (*PrivateKey, error) {
	if !bytes.Equal(algoEd, data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm")
	}
	if !bytes.Equal(algoBcrypt, data[2:4]) {
		return nil, errors.New("signify: unknown kdf algorithm")
	}

	rek, err := parseRawEncryptedKey(data)
	if err != nil {
		return nil, err
	}

	return decryptPrivateKey(rek, passphrase)
}

func ParsePublicKey(data []byte) (*PublicKey, error) {
	if !bytes.Equal(algoEd, data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm")
	}

	rpk, err := parseRawPublicKey(data)
	if err != nil {
		return nil, err
	}

	pk := PublicKey{
		Bytes:       rpk.PublicKey,
		Fingerprint: rpk.Fingerprint,
	}
	return &pk, nil
}

func ParseSignature(data []byte) (*Signature, error) {
	if !bytes.Equal(algoEd, data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm")
	}

	rs, err := parseRawSignature(data)
	if err != nil {
		return nil, err
	}

	sig := Signature{
		Bytes:       rs.Signature,
		Fingerprint: rs.Fingerprint,
	}
	return &sig, nil
}

func Sign(priv *PrivateKey, msg []byte) *Signature {
	return &Signature{
		Bytes:       *ed25519.Sign(&priv.Bytes, msg),
		Fingerprint: priv.Fingerprint,
	}
}

func Verify(pub *PublicKey, msg []byte, sig *Signature) bool {
	return ed25519.Verify(&pub.Bytes, msg, &sig.Bytes)
}
