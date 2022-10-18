package HiddenState

import (
	"github.com/protolambda/go-kzg/bls"
	"testing"
)

var testTX = []string{
	"\"Input\": [{\"Alice\", 10}, {\"Bob\", 10}], \"Output\": [{\"Alice\", 0}, {\"Bob\", 20}]",
	"\"Input\": [{\"account1\", 9000}, {\"account2\", 700}], \"Output\": [{\"account3\", 9700}]",
	"\"Input\": [{\"\nbc1qe9nagya0tvfhvymt8sejwedlukwq4a094h6ht9\", 4329001}, {\"1Kjd6178oxX3opkzpotJVhQVdgWzJKbo4m\", 10887000}], \"Output\": [{\"bc1qe9nagya0tvfhvymt8sejwedlukwq4a094h6ht9\", 15216001}]",
}

func TestKZGSettings_CheckProofSingle(t *testing.T) {
	hs := Setup(4,"1927409816240961209460912649124",16)
	poly, err := CreatePoly(hs, testTX)
	if err != nil {
		t.Fatal(err)
	}

	commitment := CommitPoly(hs, poly)
	t.Log("commitment\n", bls.StrG1(commitment))

	proof := BuildProof(hs, poly, 1)
	t.Log("proof\n", bls.StrG1(proof))

	if !CheckProof(hs, commitment, proof, poly, 1) {
		t.Fatal("could not verify proof")
	}
}