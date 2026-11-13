package uints

import (
	"math/bits"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/frontend/cs/scs"
)

// Preserve U8's comparability for callers that use it as a map key.
var _ = map[U8]bool{}

type cacheMutationCircuit struct{ A, B, Expected frontend.Variable }

func (c *cacheMutationCircuit) Define(api frontend.API) error {
	bf, err := New[U64](api)
	if err != nil {
		return err
	}
	a := NewU64(0)
	a[0] = U8{Val: c.A}
	v := bf.Xor(a, NewU64(0))
	v[0].Val = c.B
	got := bf.Xor(v, NewU64(0))
	api.AssertIsEqual(got[0].Val, c.Expected)
	return nil
}

type cacheInPlaceCircuit struct{ A, Delta, Expected frontend.Variable }

func (c *cacheInPlaceCircuit) Define(api frontend.API) error {
	bf, err := New[U64](api)
	if err != nil {
		return err
	}
	a := NewU64(0)
	a[0] = U8{Val: c.A}
	value := bf.Xor(a, NewU64(0))
	// MulAcc may mutate the underlying linear expression in place.
	value[0].Val = api.MulAcc(value[0].Val, c.Delta, 1)
	got := bf.Xor(value, NewU64(0))
	api.AssertIsEqual(got[0].Val, c.Expected)
	return nil
}

func TestCacheInPlaceMutation(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cacheInPlaceCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a, delta, want int
		valid          bool
	}{{1, 2, 3, true}, {1, 2, 1, false}, {200, 100, 44, false}, {200, 100, 200, false}} {
		w, err := frontend.NewWitness(&cacheInPlaceCircuit{tc.a, tc.delta, tc.want}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w)
		if (err == nil) != tc.valid {
			t.Fatalf("case %+v: %v", tc, err)
		}
	}
}

type cachedRotationCircuit struct {
	Input, Expected [8]frontend.Variable
	Shift           int `gnark:"-"`
}

func (c *cachedRotationCircuit) Define(api frontend.API) error {
	bf, err := New[U64](api)
	if err != nil {
		return err
	}
	var input U64
	for i := range input {
		input[i] = U8{Val: c.Input[i]}
	}
	output := bf.Lrot(input, c.Shift)
	for i := range output {
		api.AssertIsEqual(output[i].Val, c.Expected[i])
	}
	return nil
}

func TestCachedRotation(t *testing.T) {
	rng := rand.New(rand.NewSource(317))
	for _, shift := range []int{-65, -64, -1, 0, 1, 7, 8, 63, 64, 65, 129} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cachedRotationCircuit{Shift: shift})
		if err != nil {
			t.Fatal(err)
		}
		for sample := 0; sample < 5; sample++ {
			value := rng.Uint64()
			expected := bits.RotateLeft64(value, shift)
			a := cachedRotationCircuit{Shift: shift}
			for i := range a.Input {
				a.Input[i] = uint8(value >> (8 * i))
				a.Expected[i] = uint8(expected >> (8 * i))
			}
			w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(w); err != nil {
				t.Fatalf("shift %d sample %d: %v", shift, sample, err)
			}
		}
		if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
			t.Fatal("unexpected commitment")
		}
	}
}

func TestCacheMutation(t *testing.T) {
	for name, builder := range map[string]frontend.NewBuilder{"r1cs": r1cs.NewBuilder, "scs": scs.NewBuilder} {
		t.Run(name, func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &cacheMutationCircuit{})
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				a, b, want int
				valid      bool
			}{
				{1, 2, 2, true}, {1, 2, 1, false}, {1, 256, 0, false}, {1, 256, 1, false},
			} {
				w, err := frontend.NewWitness(&cacheMutationCircuit{tc.a, tc.b, tc.want}, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				err = cs.IsSolved(w)
				if (err == nil) != tc.valid {
					t.Fatalf("case %+v: %v", tc, err)
				}
			}
			if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
				t.Fatal("unexpected commitment")
			}
		})
	}
}

type foreignCacheCircuit struct{ Input frontend.Variable }

func (c *foreignCacheCircuit) Define(api frontend.API) error {
	first, err := New[U64](api)
	if err != nil {
		return err
	}
	second, err := New[U64](api)
	if err != nil {
		return err
	}
	a := NewU64(0)
	a[0] = U8{Val: c.Input}
	value := first.Xor(a, NewU64(0))
	if value[0].cache == nil {
		panic("expected cache in constraint builder")
	}
	// Simulate bits from a foreign cache with the same encoded byte value.
	// The second BinaryField must ignore them and decompose Val again.
	value[0].cache.bits = []frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0}
	got := second.Xor(value, NewU64(0))
	api.AssertIsEqual(got[0].Val, c.Input)
	return nil
}

func TestCacheOwnerIsolation(t *testing.T) {
	for name, builder := range map[string]frontend.NewBuilder{"r1cs": r1cs.NewBuilder, "scs": scs.NewBuilder} {
		t.Run(name, func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &foreignCacheCircuit{})
			if err != nil {
				t.Fatal(err)
			}
			w, err := frontend.NewWitness(&foreignCacheCircuit{Input: 19}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(w); err != nil {
				t.Fatal(err)
			}
		})
	}
}
