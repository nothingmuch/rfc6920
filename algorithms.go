package rfc6920

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
var AlgNames = map[string]int{
	"sha-256":     AlgSha256,
	"sha-256-128": AlgSha256Trunc128,
	"sha-256-120": AlgSha256Trunc120,
	"sha-256-96":  AlgSha256Trunc96,
	"sha-256-64":  AlgSha256Trunc64,
	"sha-256-32":  AlgSha256Trunc32,
	"sha-384":     AlgSha384,
	"sha-512":     AlgSha256,
}
