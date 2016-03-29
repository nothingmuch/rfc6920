package rfc6920

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
)

// Returns nil iff hash matches. Returns ErrHashMismatch if the comparison failed
// c.f. trusty urls http://arxiv.org/pdf/1401.5775.pdf
func (d Digest) Verify(blob io.Reader) error {
	hash, err := d.newHash()

	if err != nil {
		return err
	}

	io.Copy(hash, blob)

	sum := hash.Sum(nil)

	// TODO truncated hashes
	if bytes.Equal(sum, d.Value) {
		return nil
	}

	return ErrHashMismatch
}

func (d Digest) newHash() (hash.Hash, error) {

	switch d.AlgorithmID {
	case
		AlgSha256,
		AlgSha256Trunc128,
		AlgSha256Trunc120,
		AlgSha256Trunc96,
		AlgSha256Trunc64,
		AlgSha256Trunc32:
		return sha256.New(), nil
	case AlgSha384:
		return sha512.New384(), nil
	case AlgSha512:
		return sha512.New(), nil
	default:
		return nil, ErrUnknownHashAlgorithm
	}

}
