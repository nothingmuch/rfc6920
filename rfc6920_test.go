package rfc6920_test

import (
	"crypto"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	. "github.com/nothingmuch/rfc6920"
)

/* TODO

More examples from the RFC

   http://example.com/.well-known/ni/sha-256/f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk

   +-------------------------------------------------------------------+
   | .well-known URL (split over 2 lines):                             |
   | http://example.com/.well-known/ni/sha256/                         |
   | UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q                       |
   +-------------------------------------------------------------------+
   | URL Segment:                                                      |
   | sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q               |
   +-------------------------------------------------------------------+
   | Binary name (ASCII hex encoded) with 120-bit truncated hash value |
   | which is Suite ID 0x03:                                           |
   | 0353 2690 57e1 2fe2 b74b a07c 8925 60a2                           |
   +-------------------------------------------------------------------+
   | Human-speakable form of a name for this key (truncated to 120 bits|
   | in length) with checkdigit:                                       |
   | nih:sha-256-120;5326-9057-e12f-e2b7-4ba0-7c89-2560-a2;f           |
   +-------------------------------------------------------------------+
   | Human-speakable form of a name for this key (truncated to 32 bits |
   | in length) with checkdigit and no "-" separators:                 |
   | nih:sha-256-32;53269057;b                                         |
   +-------------------------------------------------------------------+
   | Human-speakable form using decimal presentation of the            |
   | algorithm ID (sha-256-120) with checkdigit:                       |
   | nih:3;532690-57e12f-e2b74b-a07c89-2560a2;f                        |
   +-------------------------------------------------------------------+

*/

func TestExamples(t *testing.T) {
	sha1table := AlgorithmTable{
		Algorithms: AlgorithmParamMap{
			"sha1": AlgorithmParams{Hash: crypto.SHA1},
		},
	}

	for uri, f := range map[string]struct {
		algorithm, authority, text string
		algorithmid, length        int
	}{
		"ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk":            {text: "Hello World!"},
		"ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk": {authority: "example.com", text: "Hello World!"},
		"ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q":            {},

		"ni:///sha-256-128;f4OxZX_x_FO5LcGBSKHWXf": {
			algorithmid: 2,
			algorithm:   "sha-256-128",
			text:        "Hello World!",
			length:      16,
		},

		"ni:///sha1;Lve95gjOVATpfV8EL5X4nxwjKHE": {
			algorithm: "sha1",
			text:      "Hello World!",
			length:    20,
		},

		// TODO relative URIs
	} {
		u, err := Parse(uri)

		assert.NoError(t, err)
		assert.NotNil(t, u)

		if f.algorithm == "" {
			f.algorithm = "sha-256"
			f.algorithmid = 1
			f.length = 32
		} else {
			// test that the stricter modes reject this test URI
			_, strictErr := StrictNoTruncation.Parse(uri)
			assert.EqualError(t, strictErr, ErrUnknownHashAlgorithm.Error())

			if f.algorithmid == 0 {
				// not truncated algorithms either
				_, noTruncErr := Strict.Parse(uri)
				assert.EqualError(t, noTruncErr, ErrUnknownHashAlgorithm.Error())
			}
		}

		assert.Equal(t, f.algorithm, u.Digest.Algorithm)

		assert.Equal(t, f.algorithmid, IANA.Algorithms[u.Digest.Algorithm].ID)

		assert.Len(t, u.Digest.Value, f.length)

		if f.authority != "" {
			assert.Equal(t, f.authority, u.Host)
		}

		if f.text != "" {
			reader := strings.NewReader(f.text)
			if f.algorithm == "sha1" {
				assert.NoError(t, sha1table.Verify(u, reader))
				assert.EqualError(t, u.Verify(reader), ErrUnknownHashAlgorithm.Error())
			} else {
				assert.NoError(t, u.Verify(reader))
			}
		}

		reader := strings.NewReader("something else")
		if f.algorithm == "sha1" {
			assert.EqualError(t, sha1table.Verify(u, reader), ErrHashMismatch.Error())
			assert.EqualError(t, u.Verify(reader), ErrUnknownHashAlgorithm.Error())
		} else {
			assert.EqualError(t, u.Verify(reader), ErrHashMismatch.Error())
		}
	}

}

func TestBadExamples(t *testing.T) {
	for uri, expErr := range map[string]error{
		"mailto:not@ahash": ErrNotNI,
		"ni://":            ErrInvalidPath,
		"ni:///":           ErrInvalidPath,
		"ni:///sha-256":    ErrInvalidPath,
		"ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk==": ErrInvalidLength,

		"ni:///sha-256-128;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk": ErrInvalidLength,
		"ni:///sha-256-128;f4OxZX_x_FO5LcGBSWX":                         ErrInvalidLength,
		"ni:///sha-256;":                                                ErrInvalidPath,
		"ni:///sha-256;f":                                               ErrInvalidLength,
		"ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGkfoo":  ErrInvalidLength,
		"ni:///sha-256;f4OxZX_x_FO5LGBSKHWXfwtSx-j1ncoSt3SABJtkGk":      ErrInvalidLength,
		"ni:///;":                                                                  ErrInvalidPath,
		"ni:///sha-253;":                                                           ErrInvalidPath,
		"ni:///sha-253;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk":                ErrUnknownHashAlgorithm,
		"ni://example.com/foo/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk": ErrUnknownHashAlgorithm,
	} {
		// get the same error if the algorithm is allowed
		u, err := Strict.Parse(uri)

		if !assert.EqualError(t, err, expErr.Error()) {
			spew.Dump(uri, u, err)
		}

		// no truncated algorithms either
		noTrunc, noTruncErr := StrictNoTruncation.Parse(uri)

		lax, laxErr := IANA.Parse(uri)

		switch err {
		case ErrNotNI, ErrInvalidPath:
			assert.Nil(t, u)
			assert.Nil(t, noTrunc)
			assert.EqualError(t, noTruncErr, err.Error())
			assert.Nil(t, lax)
			assert.EqualError(t, laxErr, err.Error())
		default:
			assert.NotNil(t, u)
			assert.Equal(t, uri, u.String())
			assert.Equal(t, uri, lax.String())

			// Parsed URLs should be the same
			assert.Equal(t, u, lax)
			assert.Equal(t, u, noTrunc)

			switch u.Algorithm {
			case "sha-256", "sha-384", "sha-512":
				assert.Equal(t, uri, noTrunc.String())
				assert.EqualError(t, noTruncErr, err.Error())
			default:
				assert.EqualError(t, noTruncErr, ErrUnknownHashAlgorithm.Error())
			}

			if _, exists := IANA.Algorithms[u.Algorithm]; exists {
				assert.EqualError(t, laxErr, err.Error(), "error for lax parsing should be the same if this is a well known algorithm")
			} else {
				assert.NoError(t, laxErr)
			}
		}
	}
}

func TestString(t *testing.T) {
	hash := crypto.SHA256.New()
	hash.Write([]byte("Hello World!"))

	ni := NI{Digest: Digest{Algorithm: "sha-256", Value: hash.Sum(nil)}}

	assert.Equal(t, "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk", ni.String())
}

func TestHashHelper(t *testing.T) {
	hash, err := DefaultAlgorithms.Hash("sha-256")
	assert.NoError(t, err)
	assert.Equal(t, crypto.SHA256, hash)

}

func TestVerifyPanics(t *testing.T) {
	assert.Panics(t, func() { TruncateHash(crypto.SHA256, -3) })
	assert.Panics(t, func() { TruncateHash(crypto.SHA256, 385) })
}

func TestTruncatePad(t *testing.T) {
	h := TruncatedHash{crypto.SHA256.New(), 999}
	sum := h.Sum(nil)
	assert.Equal(t, 999, h.Size())
	assert.Len(t, sum, 999, `"truncating" to a wider than native hash should pad with 0s because a panic would suck`)
}
