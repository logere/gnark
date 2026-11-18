package mpcsetup

import (
	"math/big"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

// referenceDIFG1 is a serial affine DIF FFT, kept deliberately close to the
// textbook definition; it serves as the golden oracle for the optimized
// Jacobian implementation. The cardinality inverse is not applied, matching
// lagrangeCoeffsG1.
func referenceDIFG1(a []curve.G1Affine, twiddles [][]fr.Element, stage int) {
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1
	t := a[0]
	a[0].Add(&a[0], &a[m])
	a[m].Sub(&t, &a[m])
	var tw big.Int
	for i := 1; i < m; i++ {
		t := a[i]
		a[i].Add(&a[i], &a[i+m])
		a[i+m].Sub(&t, &a[i+m])
		twiddles[stage][i].BigInt(&tw)
		a[i+m].ScalarMultiplication(&a[i+m], &tw)
	}
	referenceDIFG1(a[:m], twiddles, stage+1)
	referenceDIFG1(a[m:], twiddles, stage+1)
}

func referenceDIFG2(a []curve.G2Affine, twiddles [][]fr.Element, stage int) {
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1
	t := a[0]
	a[0].Add(&a[0], &a[m])
	a[m].Sub(&t, &a[m])
	var tw big.Int
	for i := 1; i < m; i++ {
		t := a[i]
		a[i].Add(&a[i], &a[i+m])
		a[i+m].Sub(&t, &a[i+m])
		twiddles[stage][i].BigInt(&tw)
		a[i+m].ScalarMultiplication(&a[i+m], &tw)
	}
	referenceDIFG2(a[:m], twiddles, stage+1)
	referenceDIFG2(a[m:], twiddles, stage+1)
}

func testPointsG1(n int) []curve.G1Affine {
	_, _, g, _ := curve.Generators()
	points := make([]curve.G1Affine, n)
	for i := range points {
		s := big.NewInt(int64(3*i + 5))
		points[i].ScalarMultiplication(&g, s)
	}
	return points
}

func testPointsG2(n int) []curve.G2Affine {
	_, _, _, g := curve.Generators()
	points := make([]curve.G2Affine, n)
	for i := range points {
		s := big.NewInt(int64(7*i + 11))
		points[i].ScalarMultiplication(&g, s)
	}
	return points
}

func TestLagrangeCoeffsG1MatchesReference(t *testing.T) {
	for _, n := range []int{8, 16, 1024} {
		sched := newTwiddleSchedule(n)
		twiddlesInv, err := fft.NewDomain(uint64(n)).TwiddlesInv()
		if err != nil {
			t.Fatal(err)
		}
		expected := testPointsG1(n)
		referenceDIFG1(expected, twiddlesInv, 0)
		bitReverse(expected)

		actual := lagrangeCoeffsG1(testPointsG1(n), n, &sched)
		for i := range actual {
			if !actual[i].Equal(&expected[i]) {
				t.Fatalf("G1 lagrange coeff %d differs at size %d", i, n)
			}
		}
	}
}

func TestLagrangeCoeffsG2MatchesReference(t *testing.T) {
	for _, n := range []int{8, 16, 1024} {
		sched := newTwiddleSchedule(n)
		twiddlesInv, err := fft.NewDomain(uint64(n)).TwiddlesInv()
		if err != nil {
			t.Fatal(err)
		}
		expected := testPointsG2(n)
		referenceDIFG2(expected, twiddlesInv, 0)
		bitReverse(expected)

		actual := lagrangeCoeffsG2(testPointsG2(n), n, &sched)
		for i := range actual {
			if !actual[i].Equal(&expected[i]) {
				t.Fatalf("G2 lagrange coeff %d differs at size %d", i, n)
			}
		}
	}
}

func TestSplitScalarRecomposes(t *testing.T) {
	lambda, _ := new(big.Int).SetString("4407920970296243842393367215006156084916469457145843978461", 10)
	r := fr.Modulus()
	check := func(s *big.Int) {
		d := splitScalar(s)
		k1 := new(big.Int).SetBytes(wordsToBytes(&d.k1))
		k2 := new(big.Int).SetBytes(wordsToBytes(&d.k2))
		if d.neg1 {
			k1.Neg(k1)
		}
		if d.neg2 {
			k2.Neg(k2)
		}
		got := new(big.Int).Mul(k2, lambda)
		got.Add(got, k1)
		got.Mod(got, r)
		want := new(big.Int).Mod(s, r)
		if got.Cmp(want) != 0 {
			t.Fatalf("GLV decomposition of %x does not recompose", s)
		}
	}
	check(big.NewInt(0))
	check(big.NewInt(1))
	check(new(big.Int).Sub(r, big.NewInt(1)))
	check(new(big.Int).Lsh(big.NewInt(1), 128))
	random := new(big.Int).Sub(r, big.NewInt(12345))
	check(random)
}

func wordsToBytes(w *[4]uint64) []byte {
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		v := w[3-i]
		for j := 0; j < 8; j++ {
			out[i*8+j] = byte(v >> (56 - 8*j))
		}
	}
	return out
}

func TestMulByDigitsMatchesScalarMultiplication(t *testing.T) {
	_, _, g1, g2 := curve.Generators()
	r := fr.Modulus()
	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		new(big.Int).Sub(r, big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 129),
		new(big.Int).Sub(r, big.NewInt(999983)),
	}
	for _, s := range scalars {
		d := splitScalar(s)

		var expectedG1 curve.G1Affine
		expectedG1.ScalarMultiplication(&g1, s)
		var baseG1, actualG1 curve.G1Jac
		baseG1.FromAffine(&g1)
		mulByDigitsG1(&actualG1, &baseG1, &d)
		var actualG1Aff curve.G1Affine
		actualG1Aff.FromJacobian(&actualG1)
		if !actualG1Aff.Equal(&expectedG1) {
			t.Fatalf("G1 mul by digits of %x differs", s)
		}

		var expectedG2 curve.G2Affine
		expectedG2.ScalarMultiplication(&g2, s)
		var baseG2, actualG2 curve.G2Jac
		baseG2.FromAffine(&g2)
		mulByDigitsG2(&actualG2, &baseG2, &d)
		var actualG2Aff curve.G2Affine
		actualG2Aff.FromJacobian(&actualG2)
		if !actualG2Aff.Equal(&expectedG2) {
			t.Fatalf("G2 mul by digits of %x differs", s)
		}
	}
}

func TestBatchJacobToAffine(t *testing.T) {
	const n = 4100 // crosses chunk boundaries
	points := testPointsG1(n)
	jac := make([]curve.G1Jac, n)
	for i := range points {
		jac[i].FromAffine(&points[i])
	}
	// include a point at infinity to exercise the zero-Z path
	jac[n/2].X.SetZero()
	jac[n/2].Y.SetZero()
	jac[n/2].Z.SetZero()
	points[n/2].X.SetZero()
	points[n/2].Y.SetZero()

	actual := make([]curve.G1Affine, n)
	batchJacobToAffineG1(actual, jac)
	for i := range actual {
		if !actual[i].Equal(&points[i]) {
			t.Fatalf("G1 batch conversion differs at %d", i)
		}
	}

	points2 := testPointsG2(n)
	jac2 := make([]curve.G2Jac, n)
	for i := range points2 {
		jac2[i].FromAffine(&points2[i])
	}
	actual2 := make([]curve.G2Affine, n)
	batchJacobToAffineG2(actual2, jac2)
	for i := range actual2 {
		if !actual2[i].Equal(&points2[i]) {
			t.Fatalf("G2 batch conversion differs at %d", i)
		}
	}
}
