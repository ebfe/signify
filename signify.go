package signify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/agl/ed25519"
)

const (
	commentHdr = "untrusted comment: "
)

var (
	algoEd     = []byte{'E', 'd'}
	algoBcrypt = []byte{'B', 'K'}
)

type PrivateKey [ed25519.PrivateKeySize]byte
type PublicKey [ed25519.PublicKeySize]byte
type Signature [ed25519.SignatureSize]byte

type rawEncryptedKey struct {
	PKAlgo      [2]byte
	KDFAlgo     [2]byte
	KDFRounds   uint32
	Salt        [16]byte
	Checksum    [8]byte
	Fingerprint [8]byte
	PrivateKey  [ed25519.PrivateKeySize]byte
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

	priv := PrivateKey(rek.PrivateKey)
	return &priv, nil
}

func ParsePublicKey(data []byte) (*PublicKey, error) {
	if !bytes.Equal(algoEd, data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm")
	}

	rpk, err := parseRawPublicKey(data)
	if err != nil {
		return nil, err
	}

	pk := PublicKey(rpk.PublicKey)
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

	sig := Signature(rs.Signature)
	return &sig, nil
}
