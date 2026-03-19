package gnark_nimue

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/stretchr/testify/assert"
)

type TestCircuit struct {
	Transcript [24]uints.U8 `gnark:",public"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	nimue, err := NewKeccakNimue(api, circuit.Transcript[:])
	if err != nil {
		return err
	}
	firstChallenge := make([]uints.U8, 8)
	err = nimue.FillChallengeBytes(firstChallenge)
	if err != nil {
		return err
	}
	firstReply := make([]uints.U8, 8)
	err = nimue.FillNextBytes(firstReply)
	if err != nil {
		return err
	}
	for i := range firstChallenge {
		api.AssertIsEqual(firstChallenge[i].Val, firstReply[i].Val)
	}
	return nil
}

func TestEndToEnd(t *testing.T) {
	circ := TestCircuit{}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	pk, vk, _ := groth16.Setup(ccs)

	transcriptBytes := []byte{231, 221, 225, 64, 121, 143, 37, 241, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	transcript := [24]uints.U8{}
	for i := range transcriptBytes {
		transcript[i] = uints.NewU8(transcriptBytes[i])
	}

	assignment := TestCircuit{
		Transcript: transcript,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	vErr := groth16.Verify(proof, vk, publicWitness)
	assert.Nil(t, vErr)
}
