package mpcsetup

import (
    "math/big"
    "runtime"
    "testing"

    curve "github.com/consensys/gnark-crypto/ecc/bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

// Compare the parallel top FFT layer with the original serial butterfly loop.
func TestParallelFFTMatchesSerial(t *testing.T) {
    previous := runtime.GOMAXPROCS(4)
    defer runtime.GOMAXPROCS(previous)
    const n = 1024
    twiddles, _ := fft.NewDomain(n).TwiddlesInv()
    _, _, g1, g2 := curve.Generators()
    points1 := make([]curve.G1Affine, 7)
    points2 := make([]curve.G2Affine, 7)
    for i := range points1 {
        scalar := big.NewInt(int64(i + 1))
        points1[i].ScalarMultiplication(&g1, scalar)
        points2[i].ScalarMultiplication(&g2, scalar)
    }
    t.Run("G1", func(t *testing.T) {
        actual := make([]curve.G1Affine, n)
        for i := range actual { actual[i] = points1[i%len(points1)] }
        expected := append([]curve.G1Affine(nil), actual...)
        m := n / 2
        butterflyG1(&expected[0], &expected[m])
        var twiddle big.Int
        for i := 1; i < m; i++ {
            butterflyG1(&expected[i], &expected[i+m])
            twiddles[0][i].BigInt(&twiddle)
            expected[i+m].ScalarMultiplication(&expected[i+m], &twiddle)
        }
        difFFTG1(expected[:m], twiddles, 1, 0, nil)
        difFFTG1(expected[m:], twiddles, 1, 0, nil)
        difFFTG1(actual, twiddles, 0, 0, nil)
        for i := range actual { if !actual[i].Equal(&expected[i]) { t.Fatalf("G1 point %d differs", i) } }
    })
    t.Run("G2", func(t *testing.T) {
        actual := make([]curve.G2Affine, n)
        for i := range actual { actual[i] = points2[i%len(points2)] }
        expected := append([]curve.G2Affine(nil), actual...)
        m := n / 2
        butterflyG2(&expected[0], &expected[m])
        var twiddle big.Int
        for i := 1; i < m; i++ {
            butterflyG2(&expected[i], &expected[i+m])
            twiddles[0][i].BigInt(&twiddle)
            expected[i+m].ScalarMultiplication(&expected[i+m], &twiddle)
        }
        difFFTG2(expected[:m], twiddles, 1, 0, nil)
        difFFTG2(expected[m:], twiddles, 1, 0, nil)
        difFFTG2(actual, twiddles, 0, 0, nil)
        for i := range actual { if !actual[i].Equal(&expected[i]) { t.Fatalf("G2 point %d differs", i) } }
    })
}
