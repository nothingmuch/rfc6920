package rfc6920

import (
	"bytes"
	"crypto"
	"fmt"
	"hash"
	"io"
)

// Returns nil iff hash matches. Returns ErrHashMismatch if the comparison failed
// c.f. trusty urls http://arxiv.org/pdf/1401.5775.pdf
func (d Digest) Verify(blob io.Reader) error {
	return DefaultAlgorithms.verify(d, blob)
}

func (t AlgorithmTable) Verify(n *NI, blob io.Reader) error {
	return t.verify(n.Digest, blob)
}

func (t AlgorithmTable) verify(d Digest, blob io.Reader) error {
	hash, err := t.TruncatedHash(d.Algorithm)

	if err != nil {
		return err
	}

	_, err = io.Copy(hash, blob)

	if err != nil {
		return err
	}

	sum := hash.Sum(nil)

	// TODO truncated hashes
	if bytes.Equal(sum, d.Value) {
		return nil
	}

	return ErrHashMismatch
}

func TruncateHash(hash crypto.Hash, size int) hash.Hash {
	if size <= 0 {
		panic(fmt.Sprintf("Invalid truncation size: %d", size))
	}

	if hash.Size() <= size {
		panic(fmt.Sprintf("Truncation %d wider than hash size %d", size, hash.Size()))
	}

	return TruncatedHash{hash.New(), size}
}

type TruncatedHash struct {
	hash.Hash
	Length int
}

func (t TruncatedHash) Size() int {
	return t.Length
}

func (t TruncatedHash) Sum(b []byte) []byte {
	sum := t.Hash.Sum(b)

	if len(sum) == t.Length {
		// this is silly
		return sum
	} else if len(sum) > t.Length {
		return sum[0:t.Length]
	} else {
		// Is this better than a panic?
		ret := make([]byte, t.Length)
		copy(ret, sum)
		return ret
	}
}
