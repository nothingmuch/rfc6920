package rfc6920_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nothingmuch/rfc6920"
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

func TestRFCExamples(t *testing.T) {
	for uri, f := range map[string]struct {
		authority, text string
	}{
		"ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk":            {"", "Hello World!"},
		"ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk": {"example.com", "Hello World!"},
		"ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q":            {"", ""},
	} {
		u, err := rfc6920.Parse(uri)

		assert.NoError(t, err)
		assert.NotNil(t, u)

		assert.Equal(t, "sha-256", u.Digest.Algorithm)
		assert.Equal(t, 1, u.Digest.AlgorithmID)
		assert.Len(t, u.Digest.Value, 32)

		if f.authority != "" {
			assert.Equal(t, f.authority, u.Host)
		}

		if f.text != "" {
			assert.NoError(t, u.Verify(strings.NewReader(f.text)))
		}
	}

}

func TestBadExamples(t *testing.T) {
	for uri, expErr := range map[string]error{
		"mailto:not@ahash": rfc6920.ErrNotNI,
		"ni://":            rfc6920.ErrInvalidPath,
		"ni:///":           rfc6920.ErrInvalidPath,
		"ni:///sha-256":    rfc6920.ErrInvalidPath,
		"ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk==": rfc6920.ErrInvalidPath,

		// "ni:///sha-256;":                                                           rfc6920.ErrInvalidPath, // TODO length checking
		// "ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGkfoo":             rfc6920.ErrInvalidPath, // TODO length checking
		// "ni:///sha-256;f4OxZX_x_FO5LGBSKHWXfwtSx-j1ncoSt3SABJtkGk":                 rfc6920.ErrInvalidPath, // TODO length checking
		// "ni:///;":                                                                  rfc6920.ErrInvalidPath, // TODO reject alg="", value=""
		// "ni:///sha-253;":                                                           rfc6920.ErrInvalidPath, // TODO reject alg="sha-253"
		// "ni:///sha-253;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk":                rfc6920.ErrInvalidPath, // TODO reject alg="sha-253"
		// "ni://example.com/foo/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk": rfc6920.ErrInvalidPath, // TODO reject alg="foo/sha-256"
	} {
		u, err := rfc6920.Parse(uri)

		// TODO determine what the correct semantics are for erroring
		// vs. returning a URI are
		assert.Error(t, err, expErr.Error())

		// TODO define the semantics of this
		if u != nil {
			assert.Equal(t, uri, u.String(), "should round trip")
		}
	}
}
