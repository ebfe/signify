package signify

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/agl/ed25519"
)

type readfiletest struct {
	file    string
	comment string
	content []byte
	parsed  interface{}
}

var readfiletests = []readfiletest{
	{
		file:    "_testdata/test.key",
		comment: "signify secret key",
		content: []byte{
			0x45, 0x64, 0x42, 0x4b, 0x00, 0x00, 0x00, 0x2a, 0xbb, 0x07, 0x17, 0x79, 0xb5, 0x84, 0x56, 0xe5,
			0xf6, 0x61, 0xdc, 0xe0, 0x44, 0x7b, 0x98, 0xd7, 0x42, 0x42, 0xc0, 0x8d, 0xc7, 0xc0, 0x52, 0x16,
			0xd3, 0xff, 0xb0, 0x73, 0xe8, 0x92, 0x09, 0x30, 0xd3, 0xdb, 0x4f, 0x63, 0xb2, 0x59, 0xa4, 0x78,
			0x26, 0x5a, 0x50, 0x04, 0xd3, 0x5a, 0xb5, 0xf8, 0x92, 0xb2, 0x75, 0x4c, 0x30, 0x12, 0x12, 0x63,
			0x6f, 0x15, 0x29, 0xd9, 0xdf, 0x41, 0x4c, 0xde, 0x4c, 0x14, 0x60, 0xb9, 0xb1, 0x14, 0x1c, 0xbc,
			0xc3, 0xde, 0xd1, 0xe7, 0x79, 0x6d, 0xd0, 0x12, 0xd7, 0xed, 0x92, 0x88, 0xf4, 0xf1, 0x6a, 0x2f,
			0x13, 0x38, 0x3d, 0x60, 0xb9, 0x35, 0x43, 0xd5},
		parsed: rawEncryptedKey{
			PKAlgo:    [2]byte{'E', 'd'},
			KDFAlgo:   [2]byte{'B', 'K'},
			KDFRounds: 42,
			Salt: [16]byte{
				0xbb, 0x07, 0x17, 0x79, 0xb5, 0x84, 0x56, 0xe5, 0xf6, 0x61, 0xdc, 0xe0, 0x44, 0x7b, 0x98, 0xd7,
			},
			Checksum:    [8]byte{0x42, 0x42, 0xc0, 0x8d, 0xc7, 0xc0, 0x52, 0x16},
			Fingerprint: [8]byte{0xd3, 0xff, 0xb0, 0x73, 0xe8, 0x92, 0x09, 0x30},
			PrivateKey: [ed25519.PrivateKeySize]byte{
				0xd3, 0xdb, 0x4f, 0x63, 0xb2, 0x59, 0xa4, 0x78,
				0x26, 0x5a, 0x50, 0x04, 0xd3, 0x5a, 0xb5, 0xf8, 0x92, 0xb2, 0x75, 0x4c, 0x30, 0x12, 0x12, 0x63,
				0x6f, 0x15, 0x29, 0xd9, 0xdf, 0x41, 0x4c, 0xde, 0x4c, 0x14, 0x60, 0xb9, 0xb1, 0x14, 0x1c, 0xbc,
				0xc3, 0xde, 0xd1, 0xe7, 0x79, 0x6d, 0xd0, 0x12, 0xd7, 0xed, 0x92, 0x88, 0xf4, 0xf1, 0x6a, 0x2f,
				0x13, 0x38, 0x3d, 0x60, 0xb9, 0x35, 0x43, 0xd5,
			},
		},
	}, {
		file:    "_testdata/test.pub",
		comment: "signify public key",
		content: []byte{
			0x45, 0x64, 0xd3, 0xff, 0xb0, 0x73, 0xe8, 0x92, 0x09, 0x30, 0xc8, 0x02, 0xe8, 0xf6, 0x4c, 0x35,
			0x63, 0xc2, 0x2e, 0xa3, 0x03, 0x56, 0xaf, 0x63, 0xf6, 0x92, 0xce, 0x2a, 0x63, 0x5c, 0xf6, 0x6e,
			0x7d, 0x48, 0x6c, 0xa8, 0x48, 0x8d, 0xe2, 0x04, 0xa6, 0x05},
		parsed: rawPublicKey{
			PKAlgo:      [2]byte{'E', 'd'},
			Fingerprint: [8]byte{0xd3, 0xff, 0xb0, 0x73, 0xe8, 0x92, 0x09, 0x30},
			PublicKey: [ed25519.PublicKeySize]byte{
				0xc8, 0x02, 0xe8, 0xf6, 0x4c, 0x35, 0x63, 0xc2, 0x2e, 0xa3, 0x03, 0x56, 0xaf, 0x63, 0xf6, 0x92,
				0xce, 0x2a, 0x63, 0x5c, 0xf6, 0x6e, 0x7d, 0x48, 0x6c, 0xa8, 0x48, 0x8d, 0xe2, 0x04, 0xa6, 0x05,
			},
		},
	}, {
		file:    "_testdata/test.msg.sig",
		comment: "signature from signify secret key",
		content: []byte{
			0x45, 0x64, 0xd3, 0xff, 0xb0, 0x73, 0xe8, 0x92, 0x09, 0x30, 0x9e, 0x9f, 0x91, 0x69, 0x08, 0x5d,
			0xa7, 0xb9, 0x1c, 0x82, 0x3c, 0x81, 0x69, 0x16, 0x16, 0x58, 0x7a, 0xd2, 0x53, 0xb4, 0xe9, 0x96,
			0x0b, 0x42, 0x3c, 0x8a, 0x40, 0x40, 0x47, 0x7e, 0xb0, 0x41, 0x74, 0x26, 0x47, 0x41, 0xa4, 0xe8,
			0x2f, 0xec, 0xfb, 0xde, 0xe2, 0x77, 0x58, 0x19, 0xca, 0xb0, 0x57, 0x5f, 0x73, 0x5f, 0x8b, 0xe2,
			0xac, 0x11, 0x00, 0x14, 0x55, 0xd6, 0xac, 0xd3, 0xd3, 0x03},
		parsed: rawSignature{
			PKAlgo:      [2]byte{'E', 'd'},
			Fingerprint: [8]byte{0xd3, 0xff, 0xb0, 0x73, 0xe8, 0x92, 0x09, 0x30},
			Signature: [ed25519.SignatureSize]byte{
				0x9e, 0x9f, 0x91, 0x69, 0x08, 0x5d, 0xa7, 0xb9, 0x1c, 0x82, 0x3c, 0x81, 0x69, 0x16, 0x16, 0x58,
				0x7a, 0xd2, 0x53, 0xb4, 0xe9, 0x96, 0x0b, 0x42, 0x3c, 0x8a, 0x40, 0x40, 0x47, 0x7e, 0xb0, 0x41,
				0x74, 0x26, 0x47, 0x41, 0xa4, 0xe8, 0x2f, 0xec, 0xfb, 0xde, 0xe2, 0x77, 0x58, 0x19, 0xca, 0xb0,
				0x57, 0x5f, 0x73, 0x5f, 0x8b, 0xe2, 0xac, 0x11, 0x00, 0x14, 0x55, 0xd6, 0xac, 0xd3, 0xd3, 0x03,
			},
		},
	},
}

func testReadFile(t *testing.T, file, comment string, content []byte) {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatalf("%s: %s\n", file, err)
	}

	rcomment, rcontent, err := ReadFile(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}

	if rcomment != comment {
		t.Errorf("%s: comment\nexpected: %q\ngot %q\n", file, comment, rcomment)
	}

	if !bytes.Equal(rcontent, content) {
		t.Errorf("%s: content\nexpected: %x\ngot %x\n", file, content, rcontent)
	}
}

func TestReadFile(t *testing.T) {
	for _, tc := range readfiletests {
		testReadFile(t, tc.file, tc.comment, tc.content)
	}
}

func TestParsePrivateKey(t *testing.T) {
	for _, tc := range readfiletests {
		want, ok := tc.parsed.(rawEncryptedKey);
		if !ok {
			continue
		}

		ek, err := ParsePrivateKey(tc.content, "")
		if err != nil {
			t.Errorf("%s: %s\n", tc.file, err)
			continue
		}

		if want != *ek {
			t.Errorf("%s: expected: %+v got: %+v\n", tc.file, want, ek)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	for _, tc := range readfiletests {
		want, ok := tc.parsed.(rawPublicKey);
		if !ok {
			continue
		}

		pub, err := ParsePublicKey(tc.content)
		if err != nil {
			t.Errorf("%s: %s\n", tc.file, err)
			continue
		}

		if want != *pub {
			t.Errorf("%s: expected: %+v got: %+v\n", tc.file, want, pub)
		}
	}
}

func TestParseSignature(t *testing.T) {
	for _, tc := range readfiletests {
		want, ok := tc.parsed.(rawSignature)
		if !ok {
			continue
		}

		sig, err := ParseSignature(tc.content)
		if err != nil {
			t.Errorf("%s: %s\n", tc.file, err)
			continue
		}

		if want != *sig {
			t.Errorf("%s: expected: %+v got: %+v\n", tc.file, want, sig)
		}
	}
}
