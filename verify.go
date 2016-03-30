package rfc6920

import (
	"bytes"
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
	hash, err := t.newHash(d.Algorithm)

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

func TruncateHash(constructor func() hash.Hash, size int) func() hash.Hash {
	if constructor().Size() <= size {
		panic(fmt.Sprintf("Truncation %d wider than hash size %d", size, constructor().Size()))
	}

	return func() hash.Hash {
		return TruncatedHash{constructor(), size}
	}
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

func (t AlgorithmTable) newHash(algName string) (hash.Hash, error) {
	if f := t.Algorithms[algName].New; f != nil {
		return f(), nil
	} else {
		return nil, ErrUnknownHashAlgorithm
	}
}
