package HiddenState

import "github.com/protolambda/go-kzg/bls"

// Lagrange interpolation on Z_p

func Interpolate(x, y []bls.Fr) []bls.Fr {
	//TODO: unfinished
	//var est []bls.Fr

	for i := 0; i < len(x); i++ {
		//prod := y[i]
		for j := 0; j < len(x); j++ {
			if i != j {
				// Can use FFT to efficient compute
				// (x - x[j]) / (x[i] - x[j])
				newpoly := make([]bls.Fr, 2, 2)

				bls.SubModFr(&newpoly[1], &x[i], &x[j])
				bls.InvModFr(&newpoly[1], &newpoly[1])

				bls.MulModFr(&newpoly[0], &x[j], &newpoly[1])
				bls.SubModFr(&newpoly[0], &bls.ZERO, &newpoly[0])


			}
		}
		//est += prod
	}

	return y
}