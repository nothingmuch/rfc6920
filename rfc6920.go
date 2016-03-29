// Parse ni:// URIs according RFC 6920
package rfc6920

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// TODO classify errors based on RFC 2119 levels
var ErrNotNI = fmt.Errorf("Not an RFC 6920 named identifier")
var ErrInvalidPath = fmt.Errorf("Not an RFC 6920 algorithm/value encoding")
var ErrUnknownHashAlgorithm = fmt.Errorf("Unknown hash algorithm")

var ErrHashMismatch = fmt.Errorf("Digest value doesn't match")

type NI struct {
	*url.URL
	Digest
}

type Digest struct {
	Algorithm   string
	AlgorithmID int
	Value       []byte
}

// TODO Functions for parsing/outputting to NIH, binary representation, embedding in HTTP, RFC 5785
// can also parse trusty URLs (FA module) in principle

// First parse use net/url.Parse, and if the scheme is correct parse the path with ParseAlgVal
func Parse(rawurl string) (*NI, error) {
	u, err := url.Parse(rawurl)

	if err != nil {
		return nil, err
	}

	if u.Scheme != "ni" {
		// TODO nih
		return nil, ErrNotNI
	}

	digest, err := ParseAlgVal(u.Path)

	// TODO parse ?ct= parameter (parse all params and expose that as a parsed mime type?)

	return &NI{u, digest}, err
}

// Parses the Path component of a named identifier URI, i.e. an "/<alg>;<base64>"
func ParseAlgVal(segment string) (digest Digest, err error) {
	if len(segment) == 0 || segment[0] != '/' {
		err = ErrInvalidPath
		return
	}

	parts := strings.Split(segment[1:], ";") // Split or SplitN? rfc says "must"

	if len(parts) != 2 {
		err = ErrInvalidPath
		return
	}

	digest.Algorithm = parts[0]

	if id, exists := AlgNames[parts[0]]; exists {
		digest.AlgorithmID = id

		// TODO validate length
	} else {
		// TODO return optional error based on algorithm table
	}

	digest.Value, err = base64.RawURLEncoding.DecodeString(parts[1])
	return
}
