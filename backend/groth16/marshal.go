package groth16

import (
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	groth16_bls12377 "github.com/logere/gnark/backend/groth16/bls12-377"
	groth16_bls12381 "github.com/logere/gnark/backend/groth16/bls12-381"
	groth16_bls24315 "github.com/logere/gnark/backend/groth16/bls24-315"
	groth16_bls24317 "github.com/logere/gnark/backend/groth16/bls24-317"
	groth16_bn254 "github.com/logere/gnark/backend/groth16/bn254"
	groth16_bw6633 "github.com/logere/gnark/backend/groth16/bw6-633"
	groth16_bw6761 "github.com/logere/gnark/backend/groth16/bw6-761"
	"github.com/logere/gnark/backend/witness"
)

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs witness.Witness
}

func NewProofWithPublicInputs(curveId ecc.ID) (*ProofWithPublicInputs, error) {
	proof := NewProof(curveId)
	witness, err := witness.New(curveId.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("new witness error %v", err)
	}
	return &ProofWithPublicInputs{
		Proof:        proof,
		PublicInputs: witness,
	}, nil
}

type Fqs = string
type Frs = string

type G1Affines struct {
	X Fqs `json:"x"`
	Y Fqs `json:"y"`
}

type Fq2s struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}
type G2Affines struct {
	X Fq2s `json:"x"`
	Y Fq2s `json:"y"`
}
type G2AffinesII struct {
	X Fqs `json:"x"`
	Y Fqs `json:"y"`
}

type ProofMap struct {
	Ar            G1Affines   `json:"pi_a"`
	Krs           G1Affines   `json:"pi_c"`
	Bs            G2Affines   `json:"pi_b"`
	Commitments   []G1Affines // Pedersen commitments a la https://eprint.iacr.org/2022/1072
	CommitmentPok G1Affines   // Batched proof of knowledge of the above commitments
	PublicInputs  []Frs       `json:"publicinputs"`
}

type ProofMapII struct {
	Ar            G1Affines   `json:"pi_a"`
	Krs           G1Affines   `json:"pi_c"`
	Bs            G2AffinesII `json:"pi_b"`
	Commitments   []G1Affines // Pedersen commitments a la https://eprint.iacr.org/2022/1072
	CommitmentPok G1Affines   // Batched proof of knowledge of the above commitments
	PublicInputs  []Frs       `json:"publicinputs"`
}

// func toJsonG1(g *bls12381.G1Affine) *ArkProofG1 {
// 	g1 := new(ArkProofG1)
// 	g1.X = g.X.String()
// 	g1.Y = g.Y.String()
// 	return g1
// }

// func toJsonFq2(g *bls12381.E2) *ArkProofE2 {
// 	g1 := new(ArkProofE2)
// 	g1.A0 = g.A0.String()
// 	g1.A1 = g.A1.String()
// 	return g1
// }
// func toJsonFr(x *fr.Element) string {
// 	a := x.String()
// 	return a
// }
// func toJsonG2(j bls12381.G2Affine) *ArkProofG2 {
// 	g := new(ArkProofG2)
// 	g.X = *toJsonArkE2(&j.X)
// 	g.Y = *toJsonArkE2(&j.Y)
// 	return g
// }

// marshal proof
func ToJson(p Proof) ([]byte, ecc.ID, error) {
	var curveID ecc.ID

	switch _proof := p.(type) {
	case *groth16_bls12377.Proof:
		var proofMap ProofMap
		curveID = ecc.BLS12_377
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2Affines{X: Fq2s{A0: _proof.Bs.X.A0.String(), A1: _proof.Bs.X.A1.String()}, Y: Fq2s{A0: _proof.Bs.Y.A0.String(), A1: _proof.Bs.Y.A1.String()}}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err
	case *groth16_bls12381.Proof:
		var proofMap ProofMap
		curveID = ecc.BLS12_381
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2Affines{X: Fq2s{A0: _proof.Bs.X.A0.String(), A1: _proof.Bs.X.A1.String()}, Y: Fq2s{A0: _proof.Bs.Y.A0.String(), A1: _proof.Bs.Y.A1.String()}}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err
	case *groth16_bn254.Proof:
		var proofMap ProofMap
		curveID = ecc.BN254
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2Affines{X: Fq2s{A0: _proof.Bs.X.A0.String(), A1: _proof.Bs.X.A1.String()}, Y: Fq2s{A0: _proof.Bs.Y.A0.String(), A1: _proof.Bs.Y.A1.String()}}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err
	case *groth16_bw6761.Proof:
		var proofMap ProofMapII
		curveID = ecc.BW6_761
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err
	case *groth16_bls24317.Proof:
		var proofMap ProofMapII
		curveID = ecc.BLS24_317
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err
	case *groth16_bls24315.Proof:
		var proofMap ProofMapII
		curveID = ecc.BLS24_315
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err

	case *groth16_bw6633.Proof:
		var proofMap ProofMapII
		curveID = ecc.BW6_633
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, curveID, err
	default:
		return nil, ecc.UNKNOWN, fmt.Errorf("unrecognized proof curve type")
	}
}

func FromJson(curveID ecc.ID, proofBytes []byte) (Proof, error) {
	switch curveID {
	case ecc.BN254:
		proof := &groth16_bn254.Proof{}
		var proofMap ProofMap

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X.A0, proofMap.Bs.X.A1)
		proof.Bs.Y.SetString(proofMap.Bs.Y.A0, proofMap.Bs.Y.A1)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil

	case ecc.BLS12_377:
		proof := &groth16_bls12377.Proof{}
		var proofMap ProofMap

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X.A0, proofMap.Bs.X.A1)
		proof.Bs.Y.SetString(proofMap.Bs.Y.A0, proofMap.Bs.Y.A1)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil
	case ecc.BLS12_381:
		proof := &groth16_bls12381.Proof{}
		var proofMap ProofMap

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal %v proof failed", curveID)
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X.A0, proofMap.Bs.X.A1)
		proof.Bs.Y.SetString(proofMap.Bs.Y.A0, proofMap.Bs.Y.A1)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil
	case ecc.BW6_761:
		proof := &groth16_bw6761.Proof{}
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X)
		proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil
	case ecc.BLS24_317:
		proof := &groth16_bls24317.Proof{}
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		// X: E4 {B0: {A0, A1}, B1: {A0, A1}}, proofMap.Bs.X = B0.A0.String() + "+" + B0.A1.String() + "*u" + "+(" + B1.A0.String() + "+" + B1.A1.String() + "*u" + ")*v"
		// var lenX = len(proofMap.Bs.X)
		// var s1, s2, s3, s4 := (lenX - 10)/4, (lenX - 10)/2
		// proof.Bs.X.SetString(proofMap.Bs.X[])
		// proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil
	case ecc.BLS24_315:
		proof := &groth16_bls24315.Proof{}
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		// proof.Bs.X.SetString(proofMap.Bs.X)
		// proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil
	case ecc.BW6_633:
		proof := &groth16_bw6633.Proof{}
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return nil, fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X)
		proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)

		return proof, nil
	default:
		return nil, fmt.Errorf("unrecognized proof curve type")
	}
}

func (p ProofWithPublicInputs) Marshal() ([]byte, error) {

	switch _proof := p.Proof.(type) {
	case *groth16_bls12377.Proof:
		var proofMap ProofMap
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2Affines{X: Fq2s{A0: _proof.Bs.X.A0.String(), A1: _proof.Bs.X.A1.String()}, Y: Fq2s{A0: _proof.Bs.Y.A0.String(), A1: _proof.Bs.Y.A1.String()}}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}

		vectors := p.PublicInputs.Vector().(fr_bls12377.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}

		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err
	case *groth16_bls12381.Proof:
		var proofMap ProofMap
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2Affines{X: Fq2s{A0: _proof.Bs.X.A0.String(), A1: _proof.Bs.X.A1.String()}, Y: Fq2s{A0: _proof.Bs.Y.A0.String(), A1: _proof.Bs.Y.A1.String()}}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		vectors := p.PublicInputs.Vector().(fr_bls12381.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err
	case *groth16_bn254.Proof:
		var proofMap ProofMap
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2Affines{X: Fq2s{A0: _proof.Bs.X.A0.String(), A1: _proof.Bs.X.A1.String()}, Y: Fq2s{A0: _proof.Bs.Y.A0.String(), A1: _proof.Bs.Y.A1.String()}}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		vectors := p.PublicInputs.Vector().(fr_bn254.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err
	case *groth16_bw6761.Proof:
		var proofMap ProofMapII
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		vectors := p.PublicInputs.Vector().(fr_bw6761.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err
	case *groth16_bls24317.Proof:
		var proofMap ProofMapII
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		vectors := p.PublicInputs.Vector().(fr_bls24317.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err
	case *groth16_bls24315.Proof:
		var proofMap ProofMapII
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		vectors := p.PublicInputs.Vector().(fr_bls24315.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err

	case *groth16_bw6633.Proof:
		var proofMap ProofMapII
		proofMap.Ar = G1Affines{X: _proof.Ar.X.String(), Y: _proof.Ar.Y.String()}
		proofMap.Bs = G2AffinesII{X: _proof.Bs.X.String(), Y: _proof.Bs.Y.String()}
		proofMap.Krs = G1Affines{X: _proof.Krs.X.String(), Y: _proof.Krs.Y.String()}
		proofMap.Commitments = make([]G1Affines, len(_proof.Commitments))
		for i, Commitment := range _proof.Commitments {
			proofMap.Commitments[i] = G1Affines{X: Commitment.X.String(), Y: Commitment.Y.String()}
		}
		proofMap.CommitmentPok = G1Affines{X: _proof.CommitmentPok.X.String(), Y: _proof.CommitmentPok.X.String()}
		vectors := p.PublicInputs.Vector().(fr_bw6633.Vector)
		proofMap.PublicInputs = make([]Frs, len(vectors))
		for i, vec := range vectors {
			proofMap.PublicInputs[i] = vec.String()
		}
		proofBytes, err := json.Marshal(proofMap)
		return proofBytes, err
	default:
		return nil, fmt.Errorf("unrecognized proof curve type")
	}
}

func (p *ProofWithPublicInputs) Unmarshal(proofBytes []byte) error {

	switch proof := p.Proof.(type) {
	case *groth16_bn254.Proof:
		var proofMap ProofMap

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X.A0, proofMap.Bs.X.A1)
		proof.Bs.Y.SetString(proofMap.Bs.Y.A0, proofMap.Bs.Y.A1)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bn254.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil

	case *groth16_bls12377.Proof:
		var proofMap ProofMap

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X.A0, proofMap.Bs.X.A1)
		proof.Bs.Y.SetString(proofMap.Bs.Y.A0, proofMap.Bs.Y.A1)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bls12377.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil
	case *groth16_bls12381.Proof:
		var proofMap ProofMap

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X.A0, proofMap.Bs.X.A1)
		proof.Bs.Y.SetString(proofMap.Bs.Y.A0, proofMap.Bs.Y.A1)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bls12381.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil
	case *groth16_bw6761.Proof:
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X)
		proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bw6761.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil
	case *groth16_bls24317.Proof:
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		// X: E4 {B0: {A0, A1}, B1: {A0, A1}}, proofMap.Bs.X = B0.A0.String() + "+" + B0.A1.String() + "*u" + "+(" + B1.A0.String() + "+" + B1.A1.String() + "*u" + ")*v"
		// var lenX = len(proofMap.Bs.X)
		// var s1, s2, s3, s4 := (lenX - 10)/4, (lenX - 10)/2
		// proof.Bs.X.SetString(proofMap.Bs.X[])
		// proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bls24317.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil
	case *groth16_bls24315.Proof:
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		// proof.Bs.X.SetString(proofMap.Bs.X)
		// proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bls24315.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil
	case *groth16_bw6633.Proof:
		var proofMap ProofMapII

		if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
			return fmt.Errorf("Unmarshal proof failed")
		}

		proof.Ar.X.SetString(proofMap.Ar.X)
		proof.Ar.Y.SetString(proofMap.Ar.Y)

		proof.Bs.X.SetString(proofMap.Bs.X)
		proof.Bs.Y.SetString(proofMap.Bs.Y)
		proof.Krs.X.SetString(proofMap.Krs.X)
		proof.Krs.Y.SetString(proofMap.Krs.Y)

		for i, Commitment := range proofMap.Commitments {
			proof.Commitments[i].X.SetString(Commitment.X)
			proof.Commitments[i].Y.SetString(Commitment.Y)
		}
		proof.CommitmentPok.X.SetString(proofMap.CommitmentPok.X)
		proof.CommitmentPok.Y.SetString(proofMap.CommitmentPok.Y)
		vectors := make(chan any, len(proofMap.PublicInputs))
		for _, w := range proofMap.PublicInputs {
			x := new(fr_bw6633.Element)
			x.SetString(w)
			vectors <- x
		}
		p.PublicInputs.Fill(len(proofMap.PublicInputs), 0, vectors)

		return nil
	default:
		return fmt.Errorf("unrecognized proof curve type")
	}
}
