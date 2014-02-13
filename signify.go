package signify

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	commentHdr = "untrusted comment: "
)

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
