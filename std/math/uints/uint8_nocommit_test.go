package uints

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type noCommitBitwiseCircuit struct {
	A, B          [8]frontend.Variable
	XOR, AND, NOT [8]frontend.Variable
}

func (c *noCommitBitwiseCircuit) Define(api frontend.API) error {
	field, err := New[U64](api)
	if err != nil {
		return err
	}
	var a, b U64
	for i := range a {
		a[i] = U8{Val: c.A[i]}
		b[i] = U8{Val: c.B[i]}
	}
	x, y, z := field.Xor(a, b), field.And(a, b), field.Not(a)
	for i := range x {
		api.AssertIsEqual(x[i].Val, c.XOR[i])
		api.AssertIsEqual(y[i].Val, c.AND[i])
		api.AssertIsEqual(z[i].Val, c.NOT[i])
	}
	return nil
}

func TestBitwiseOperationsWithoutCommitments(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &noCommitBitwiseCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("bitwise circuit contains %d commitments", n)
	}
	rng := rand.New(rand.NewSource(43))
	for sample := 0; sample < 32; sample++ {
		var assignment noCommitBitwiseCircuit
		for i := range assignment.A {
			a, b := byte(rng.Uint32()), byte(rng.Uint32())
			if sample == 0 {
				a, b = 0, 0xff
			} else if sample == 1 {
				a, b = 0xff, 0xff
			}
			assignment.A[i], assignment.B[i] = a, b
			assignment.XOR[i], assignment.AND[i], assignment.NOT[i] = a^b, a&b, ^a
		}
		witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(witness); err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
		if sample == 0 {
			badCases := map[string]func(*noCommitBitwiseCircuit){
				"XOR":               func(c *noCommitBitwiseCircuit) { c.XOR[0] = byte(0) },
				"AND":               func(c *noCommitBitwiseCircuit) { c.AND[0] = byte(1) },
				"NOT":               func(c *noCommitBitwiseCircuit) { c.NOT[0] = byte(0) },
				"out-of-range byte": func(c *noCommitBitwiseCircuit) { c.A[0] = 256 },
			}
			for name, mutate := range badCases {
				badAssignment := assignment
				mutate(&badAssignment)
				bad, err := frontend.NewWitness(&badAssignment, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := ccs.IsSolved(bad); err == nil {
					t.Errorf("accepted %s", name)
				}
			}
		}
	}
}
