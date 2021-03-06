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
var ErrInvalidPath = fmt.Errorf("Invalid Path (not an RFC 6920 algorithm/value encoding)")
var ErrInvalidLength = fmt.Errorf("Incorrect length for specificied algorithm")
var ErrUnknownHashAlgorithm = fmt.Errorf("Unknown hash algorithm")

var ErrHashMismatch = fmt.Errorf("Digest value doesn't match")

type NI struct {
	*url.URL
	Digest
}

func (ni NI) String() string {
	uri := ni.URL

	if uri == nil {
		uri = &url.URL{
			Scheme: "ni",
			Path: fmt.Sprintf("/%s;%s",
				ni.Digest.Algorithm,
				base64.RawURLEncoding.EncodeToString(ni.Digest.Value),
			),
		}
	}

	return uri.String()
}

type Digest struct {
	Algorithm string
	Value     []byte
}

func (d Digest) Sum() []byte {
	return d.Value
}

// TODO Functions for parsing/outputting to NIH, binary representation, embedding in HTTP, RFC 5785
// can also parse trusty URLs (FA module) in principle

// First parse use net/url.Parse, and if the scheme is correct parse the path with ParseAlgVal
func Parse(rawurl string) (*NI, error) {
	return DefaultAlgorithms.Parse(rawurl)
}

func (t AlgorithmTable) Parse(rawurl string) (*NI, error) {
	u, err := url.Parse(rawurl)

	if err != nil {
		return nil, err
	}

	if u.Scheme != "ni" {
		// TODO nih
		// TODO relative URIs?
		return nil, ErrNotNI
	}

	digest, err := t.ParseAlgVal(u.Path)

	if digest == nil {
		return nil, err
	}

	// TODO parse ?ct= parameter (parse all params and expose that as a parsed mime type?)

	return &NI{u, *digest}, err
}

// Parses the Path component of a named identifier URI, i.e. an "/<alg>;<base64>"
func ParseAlgVal(segment string) (digest *Digest, err error) {
	return DefaultAlgorithms.ParseAlgVal(segment)
}

func (t AlgorithmTable) ParseAlgVal(segment string) (*Digest, error) {
	algName, encoded, err := splitPathSegment(segment)

	if err != nil {
		return nil, err
	}

	// TODO check length before decoding?
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(encoded)

	digest := Digest{
		Algorithm: algName,
		Value:     decoded,
	}

	validationErr := t.CheckLength(digest)

	if validationErr != nil {
		err = validationErr
	} else if decodeErr != nil {
		err = decodeErr
	}

	return &digest, err
}

func splitPathSegment(segment string) (string, string, error) {
	if len(segment) == 0 || segment[0] != '/' {
		return "", "", ErrInvalidPath
	}

	parts := strings.Split(segment[1:], ";") // Split or SplitN? rfc says "must"

	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", ErrInvalidPath
	} else {
		return parts[0], parts[1], nil
	}
}

func (t AlgorithmTable) CheckLength(digest Digest) error {
	algParams, known := t.Algorithms[digest.Algorithm]

	if known {
		// We only check lengths of known algorithms
		// If we know the expected length, verify it.
		if algParams.Length != 0 {
			if len(digest.Value) != algParams.Length {
				return ErrInvalidLength
			}
		}

		// no hash is always an error
		if len(digest.Value) == 0 {
			return ErrInvalidLength
		}
	} else if t.Strict {
		return ErrUnknownHashAlgorithm
	}

	return nil
}
