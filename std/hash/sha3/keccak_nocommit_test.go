package sha3

import (
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/std/math/uints"
	native "golang.org/x/crypto/sha3"
)

type noCommitKeccakCircuit struct {
	Input  []frontend.Variable
	Digest [32]frontend.Variable `gnark:",public"`
}

func (c *noCommitKeccakCircuit) Define(api frontend.API) error {
	h, err := NewLegacyKeccak256(api)
	if err != nil {
		return err
	}
	input := make([]uints.U8, len(c.Input))
	for i, v := range c.Input {
		api.ToBinary(v, 8)
		input[i] = uints.U8{Val: v}
	}
	h.Write(input)
	for i, v := range h.Sum() {
		api.AssertIsEqual(v.Val, c.Digest[i])
	}
	return nil
}

func TestKeccak256WithoutCommitments(t *testing.T) {
	// Include both sides of Keccak-256's 136-byte block boundary.
	for _, size := range []int{0, 32, 135, 136, 137} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			circuit := &noCommitKeccakCircuit{Input: make([]frontend.Variable, size)}
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
			if err != nil {
				t.Fatal(err)
			}
			if n := len(ccs.GetCommitments().CommitmentIndexes()); n != 0 {
				t.Fatalf("Keccak circuit contains %d commitments", n)
			}
			message := make([]byte, size)
			assignment := &noCommitKeccakCircuit{Input: make([]frontend.Variable, size)}
			for i := range message {
				message[i] = byte(i)
				assignment.Input[i] = message[i]
			}
			h := native.NewLegacyKeccak256()
			_, _ = h.Write(message)
			digest := h.Sum(nil)
			for i := range digest {
				assignment.Digest[i] = digest[i]
			}
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(witness); err != nil {
				t.Fatal(err)
			}
			if size != 32 {
				return
			}
			pk, vk, err := groth16.Setup(ccs)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := groth16.Prove(ccs, pk, witness)
			if err != nil {
				t.Fatal(err)
			}
			public, err := witness.Public()
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, public); err != nil {
				t.Fatal(err)
			}
			assignment.Digest[0] = digest[0] ^ 1
			bad, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			badPublic, err := bad.Public()
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, badPublic); err == nil {
				t.Fatal("proof accepted an altered public digest")
			}
		})
	}
}
