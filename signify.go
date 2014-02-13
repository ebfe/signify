package signify

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/agl/ed25519"
	"io"
	"strings"
)

const (
	commentHdr = "untrusted comment: "
)

type encryptedKey struct {
	PKAlgo      [2]byte
	KDFAlgo     [2]byte
	KDFRounds   uint32
	Salt        [16]byte
	Checksum    [8]byte
	Fingerprint [8]byte
	PrivateKey  [ed25519.PrivateKeySize]byte
}

type pubkey struct {
	PKAlgo      [2]byte
	Fingerprint [8]byte
	PublicKey   [ed25519.PublicKeySize]byte
}

type sig struct {
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
