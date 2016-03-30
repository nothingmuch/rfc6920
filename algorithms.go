package rfc6920

import (
	"crypto/sha256"
	"crypto/sha512"
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
		"sha-256":     {AlgSha256, 256 / 8, sha256.New},
		"sha-256-128": {AlgSha256Trunc128, 128 / 8, TruncateHash(sha256.New, 128/8)},
		"sha-256-120": {AlgSha256Trunc120, 120 / 8, TruncateHash(sha256.New, 120/8)},
		"sha-256-96":  {AlgSha256Trunc96, 96 / 8, TruncateHash(sha256.New, 96/8)},
		"sha-256-64":  {AlgSha256Trunc64, 64 / 8, TruncateHash(sha256.New, 64/8)},
		"sha-256-32":  {AlgSha256Trunc32, 32 / 8, TruncateHash(sha256.New, 32/8)},

		"sha-384": {AlgSha384, 384 / 8, sha512.New384},
		"sha-512": {AlgSha512, 512 / 8, sha512.New},
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
		"sha-256": {AlgSha256, 256 / 8, sha256.New},
		"sha-384": {AlgSha384, 384 / 8, sha512.New384},
		"sha-512": {AlgSha512, 512 / 8, sha512.New},
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
	ID     int              // an identifier for the binary encoding (rfc6920 s6)
	Length int              // in bytes, for validating length
	New    func() hash.Hash // a function to call to make a new hasher
}
