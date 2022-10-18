package HiddenState

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

type HiddenStateSettings struct {
	size uint64
	ks *kzg.KZGSettings
}

// one way function F: string -> uint64
func owf(str string) uint64 {
	h := md5.New()
	h.Write([]byte(str))
	d := h.Sum(nil)

	var ret uint64
	buf := bytes.NewBuffer(d)
	err := binary.Read(buf, binary.BigEndian, &ret)
	if err != nil {
		panic(err.Error())
		return 0
	}

	return ret
}

// Lagrange interpolation to get the coefficients of psi
func lagrangeInterpolate(x, y []bls.Fr) []bls.Fr {
	return Interpolate(x, y)
}

func Setup(scale uint8, secret string, n uint64) *HiddenStateSettings {
	fs := kzg.NewFFTSettings(scale)
	s1, s2 := kzg.GenerateTestingSetup(secret, n+1)
	kzgsettings := kzg.NewKZGSettings(fs, s1, s2)

	hs := &HiddenStateSettings{
		size: n,
		ks:   kzgsettings,
	}
	return hs
}

func CreatePoly(hs *HiddenStateSettings, TX []string) ([]bls.Fr, error) {
	if len(TX) == 0 {
		return nil, errors.New("TX size is 0!")
	}

	if uint64(len(TX)) > hs.size {
		return nil, errors.New("TX size is larger than max size!")
	}

	n := len(TX)
	x := make([]bls.Fr, n, n)
	y := make([]bls.Fr, n, n)
	for i := 0; i < n; i++ {
		bls.AsFr(&x[i], uint64(i))
		bls.AsFr(&y[i], owf(TX[i]))
	}

	poly := lagrangeInterpolate(x, y)

	return poly, nil
}

// KZG commitment to TX in coefficient form
func CommitPoly(hs *HiddenStateSettings, poly []bls.Fr) *bls.G1Point {
	return hs.ks.CommitToPoly(poly)
}

// Compute proof pi_i for TX_i
func BuildProof(hs *HiddenStateSettings, poly []bls.Fr, i uint64) *bls.G1Point {
	return hs.ks.ComputeProofSingle(poly, i)
}

// Check whether pi_i is a valid proof for TX_i
func CheckProof(hs *HiddenStateSettings, commitment, proof *bls.G1Point, poly []bls.Fr, i uint64) bool {
	var x bls.Fr
	bls.AsFr(&x, i)
	var value bls.Fr
	bls.EvalPolyAt(&value, poly, &x)

	return hs.ks.CheckProofSingle(commitment, proof, &x, &value)
}
