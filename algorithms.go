package rfc6920

import (
	"crypto"
	"hash"
)

// From IANA registered NI algorithms, 2016-03-29
// https://www.iana.org/assignments/named-information/named-information.xhtml
const (
	AlgSha256         = 1
	AlgSha256Trunc128 = 2
	AlgSha256Trunc120 = 3
	AlgSha256Trunc96  = 4
	AlgSha256Trunc64  = 5
	AlgSha256Trunc32  = 6
	AlgSha384         = 7
	AlgSha512         = 8
)

// TODO make a DefaultAlgorithms var that the public function uses, that
// encapsulates this table in a proper type. For now let's pretend it's not
// global

// The default is to allow arbitrary algorithms and truncations
var DefaultAlgorithms = IANA

var IANA = AlgorithmTable{
	Strict: false,
	Algorithms: AlgorithmParamMap{
		// RFC says MUST have sha-256, MAY truncate
		"sha-256":     {AlgSha256, 256 / 8, crypto.SHA256, 0},
		"sha-256-128": {AlgSha256Trunc128, 128 / 8, crypto.SHA256, 128 / 8},
		"sha-256-120": {AlgSha256Trunc120, 120 / 8, crypto.SHA256, 120 / 8},
		"sha-256-96":  {AlgSha256Trunc96, 96 / 8, crypto.SHA256, 96 / 8},
		"sha-256-64":  {AlgSha256Trunc64, 64 / 8, crypto.SHA256, 64 / 8},
		"sha-256-32":  {AlgSha256Trunc32, 32 / 8, crypto.SHA256, 32 / 8},

		"sha-384": {AlgSha384, 384 / 8, crypto.SHA384, 0},
		"sha-512": {AlgSha512, 512 / 8, crypto.SHA512, 0},
	},
}

var Strict = AlgorithmTable{
	Strict:     true,
	Algorithms: IANA.Algorithms,
}

// The RFC says programs MAY accept additional algorithms and MAY allow truncation.
var StrictNoTruncation = AlgorithmTable{
	Strict: true, // refuse additional algorithms
	Algorithms: AlgorithmParamMap{
		// don't allow truncated algorithms
		"sha-256": {AlgSha256, 256 / 8, crypto.SHA256, 0},
		"sha-384": {AlgSha384, 384 / 8, crypto.SHA384, 0},
		"sha-512": {AlgSha512, 512 / 8, crypto.SHA512, 0},
	},
}

// This type controls recognition of well known hash algorithms.
type AlgorithmTable struct {
	Strict     bool // unrecognized algorithms are an error
	Algorithms AlgorithmParamMap
}

type AlgorithmParamMap map[string]AlgorithmParams

// These may be zero for unset
type AlgorithmParams struct {
	ID       int // an identifier for the binary encoding (rfc6920 s6)
	Length   int // in bytes, for validating length
	Hash     crypto.Hash
	Truncate int // if != 0, truncate to this length in bytes
}

func (t AlgorithmTable) AlgorithmParams(algName string) (AlgorithmParams, error) {
	if alg, ok := t.Algorithms[algName]; ok && alg.Hash != 0 {
		return alg, nil
	} else {
		return AlgorithmParams{}, ErrUnknownHashAlgorithm
	}

}

func (t AlgorithmTable) Hash(algName string) (crypto.Hash, error) {
	p, err := t.AlgorithmParams(algName)
	return p.Hash, err
}

func (t AlgorithmTable) TruncatedHash(algName string) (hash.Hash, error) {
	p, err := t.AlgorithmParams(algName)

	if err != nil {
		return nil, err
	}

	if p.Truncate != 0 {
		return TruncateHash(p.Hash, p.Truncate), nil
	} else {
		return p.Hash.New(), nil
	}
}
