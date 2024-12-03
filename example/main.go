package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
	"github.com/reilabs/gnark-nimue/hash"
	"math/bits"
)

type TestCircuit struct {
	IO         []byte
	Transcript [24]uints.U8 `gnark:",public"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	arthur, err := gnark_nimue.NewKeccakArthur(api, circuit.IO, circuit.Transcript[:])

	if err != nil {
		return err
	}

	firstChallenge := make([]uints.U8, 8)
	err = arthur.FillChallengeBytes(firstChallenge)
	if err != nil {
		return err
	}
	firstReply := make([]uints.U8, 8)
	err = arthur.FillNextBytes(firstReply)
	if err != nil {
		return err
	}
	for i := range firstChallenge {
		api.AssertIsEqual(firstChallenge[i].Val, firstReply[i].Val)
	}

	secondChallenge := make([]uints.U8, 16)
	err = arthur.FillChallengeBytes(secondChallenge)
	if err != nil {
		return err
	}
	secondReply := make([]uints.U8, 16)
	err = arthur.FillNextBytes(secondReply)
	if err != nil {
		return err
	}
	for i := range secondChallenge {
		api.AssertIsEqual(secondChallenge[i].Val, secondReply[i].Val)
	}

	return nil
}

func Example1() {
	// the protocol has two rounds in which the verifier sends 8/16 bytes of randomness and the prover must send it back
	badIOPat := "bad-protocol\u0000S8first challenge\u0000A8first reply\u0000S16second challenge\u0000A16second reply"
	io := gnark_nimue.IOPattern{}
	_ = io.Parse([]byte(badIOPat))
	fmt.Printf("io: %s\n", io.PPrint())

	circ := TestCircuit{
		IO: []byte(badIOPat),
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	pk, vk, _ := groth16.Setup(ccs)

	transcriptBytes := []byte{9, 2, 243, 247, 30, 73, 172, 83, 203, 176, 231, 217, 99, 6, 2, 176, 93, 1, 93, 32, 162, 116, 211, 219}

	transcript := [24]uints.U8(uints.NewU8Array(transcriptBytes[:]))

	assignment := TestCircuit{
		IO:         []byte(badIOPat),
		Transcript: transcript,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	vErr := groth16.Verify(proof, vk, publicWitness)
	fmt.Printf("%v\n", vErr)
}

type WhirCircuit struct {
	IO         []byte
	Transcript [2312]uints.U8 `gnark:",public"`
}

func (circuit *WhirCircuit) Define(api frontend.API) error {
	arthur, err := gnark_nimue.NewKeccakArthur(api, circuit.IO, circuit.Transcript[:])
	if err != nil {
		return err
	}

	merkleRoot := make([]uints.U8, 32)
	err = arthur.FillNextBytes(merkleRoot)
	if err != nil {
		return err
	}
	rootVars := make([]frontend.Variable, 32)
	for i := range merkleRoot {
		rootVars[i] = merkleRoot[i].Val
	}
	api.Println(rootVars...)

	oodCh := [1]frontend.Variable{}
	err = arthur.FillChallengeScalars(oodCh[:])
	if err != nil {
		return err
	}
	api.Println(oodCh[:]...)

	oodAns := [1]frontend.Variable{}
	err = arthur.FillNextScalars(oodAns[:])
	if err != nil {
		return err
	}
	api.Println(oodAns[:]...)

	initialCombinationRandomness := [1]frontend.Variable{}
	err = arthur.FillChallengeScalars(initialCombinationRandomness[:])
	if err != nil {
		return err
	}
	api.Println(initialCombinationRandomness[0])

	for range 4 {
		sumcheckPolyEvals := [3]frontend.Variable{}
		err = arthur.FillNextScalars(sumcheckPolyEvals[:])
		if err != nil {
			return err
		}
		api.Println(sumcheckPolyEvals[:]...)

		foldingRandomnessSingle := [1]frontend.Variable{}
		err = arthur.FillChallengeScalars(foldingRandomnessSingle[:])
		if err != nil {
			return err
		}
		api.Println(foldingRandomnessSingle[0])
	}

	return nil
}

func ExampleWhir() {

	ioPat := "🌪\ufe0f\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S47initial_combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S246stir_queries\u0000S32pow_queries\u0000A8pow-nonce\u0000S47combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S42stir_queries\u0000S32pow_queries\u0000A8pow-nonce\u0000S47combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S24stir_queries\u0000S32pow_queries\u0000A8pow-nonce\u0000S47combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S18stir_queries\u0000S32pow_queries\u0000A8pow-nonce\u0000S47combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32final_coeffs\u0000S14final_queries\u0000S32pow_queries\u0000A8pow-nonce"
	io := gnark_nimue.IOPattern{}
	_ = io.Parse([]byte(ioPat))
	fmt.Printf("io: %s\n", io.PPrint())

	circ := WhirCircuit{
		IO: []byte(ioPat),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	if err != nil {
		fmt.Println(err)
		return
	}
	pk, vk, _ := groth16.Setup(ccs)

	transcriptBytes := [2312]byte{87, 185, 236, 158, 191, 94, 0, 231, 238, 211, 192, 186, 214, 75, 100, 146, 70, 205, 148, 111, 212, 159, 189, 24, 133, 148, 249, 15, 115, 111, 196, 121, 135, 161, 80, 122, 19, 19, 233, 232, 181, 197, 70, 8, 212, 80, 150, 245, 202, 64, 72, 187, 56, 241, 42, 254, 231, 229, 105, 128, 133, 27, 76, 40, 88, 120, 111, 43, 112, 48, 112, 158, 10, 249, 193, 212, 55, 196, 153, 147, 89, 70, 185, 173, 252, 43, 180, 82, 242, 220, 202, 151, 116, 33, 54, 18, 47, 41, 225, 78, 163, 226, 120, 74, 171, 204, 132, 51, 156, 140, 252, 97, 113, 250, 142, 13, 60, 197, 118, 171, 245, 8, 159, 232, 16, 250, 21, 22, 192, 89, 99, 186, 101, 64, 205, 53, 96, 199, 156, 105, 110, 249, 74, 23, 4, 174, 185, 89, 43, 116, 229, 124, 162, 5, 11, 141, 213, 3, 2, 25, 164, 183, 159, 94, 149, 247, 19, 218, 240, 85, 255, 161, 162, 54, 173, 3, 44, 143, 231, 97, 88, 134, 212, 30, 201, 171, 46, 26, 39, 202, 210, 33, 92, 114, 238, 219, 148, 110, 62, 68, 188, 172, 29, 149, 122, 159, 84, 112, 247, 144, 170, 43, 246, 22, 77, 25, 61, 249, 94, 228, 6, 111, 112, 27, 3, 71, 240, 133, 69, 27, 92, 33, 20, 248, 81, 224, 87, 30, 240, 69, 36, 242, 21, 161, 233, 241, 91, 42, 41, 143, 186, 52, 30, 98, 161, 41, 178, 225, 52, 217, 71, 191, 247, 28, 90, 161, 137, 204, 152, 89, 251, 139, 147, 65, 211, 53, 158, 54, 29, 224, 174, 222, 75, 230, 165, 219, 214, 36, 162, 207, 226, 208, 187, 179, 142, 94, 82, 92, 224, 71, 193, 166, 238, 56, 106, 39, 250, 198, 102, 21, 82, 248, 41, 220, 77, 164, 25, 56, 151, 14, 104, 18, 36, 90, 50, 254, 81, 173, 47, 104, 47, 13, 3, 160, 199, 20, 17, 165, 149, 241, 62, 225, 10, 87, 240, 80, 111, 245, 23, 127, 71, 17, 9, 127, 124, 159, 69, 63, 111, 25, 148, 86, 160, 2, 202, 82, 92, 172, 151, 171, 152, 10, 236, 77, 182, 119, 98, 40, 91, 55, 29, 11, 109, 37, 158, 191, 128, 20, 69, 238, 68, 203, 191, 19, 56, 38, 218, 79, 54, 188, 77, 233, 121, 56, 143, 174, 124, 188, 53, 180, 49, 67, 232, 61, 150, 44, 86, 224, 193, 186, 125, 248, 254, 102, 157, 181, 174, 174, 73, 139, 55, 9, 28, 37, 225, 225, 78, 189, 122, 16, 153, 242, 255, 168, 253, 8, 120, 19, 94, 7, 3, 84, 60, 99, 104, 241, 7, 34, 138, 31, 137, 254, 65, 33, 166, 242, 195, 236, 38, 44, 139, 243, 244, 201, 17, 104, 201, 52, 190, 23, 199, 167, 230, 165, 249, 5, 123, 187, 123, 218, 211, 76, 174, 197, 112, 202, 186, 164, 96, 249, 112, 130, 240, 110, 119, 85, 187, 87, 83, 224, 146, 26, 0, 0, 0, 0, 0, 9, 109, 64, 254, 9, 55, 39, 22, 185, 99, 224, 254, 123, 36, 149, 105, 175, 218, 200, 145, 167, 153, 120, 146, 197, 134, 218, 111, 146, 146, 134, 245, 135, 141, 32, 136, 22, 43, 231, 107, 85, 77, 194, 127, 164, 209, 174, 93, 202, 128, 182, 97, 48, 78, 28, 248, 153, 90, 241, 68, 186, 184, 255, 255, 180, 29, 39, 147, 144, 43, 255, 46, 109, 146, 124, 191, 162, 228, 163, 122, 42, 234, 132, 114, 170, 39, 181, 50, 119, 221, 67, 163, 243, 108, 104, 205, 173, 226, 7, 1, 81, 148, 231, 104, 214, 38, 211, 181, 57, 174, 207, 118, 174, 0, 93, 25, 16, 220, 29, 45, 177, 61, 104, 150, 18, 240, 252, 148, 154, 245, 14, 132, 112, 222, 240, 214, 177, 27, 134, 189, 104, 32, 33, 99, 61, 199, 135, 93, 86, 122, 156, 194, 109, 15, 202, 31, 82, 201, 52, 28, 153, 159, 24, 135, 237, 23, 209, 80, 44, 4, 121, 27, 163, 33, 102, 47, 32, 87, 180, 136, 69, 0, 142, 50, 49, 135, 88, 241, 88, 26, 92, 185, 147, 178, 29, 152, 93, 112, 17, 8, 86, 90, 222, 123, 86, 115, 121, 240, 223, 59, 30, 48, 80, 107, 168, 239, 9, 154, 55, 184, 86, 86, 154, 176, 43, 248, 35, 160, 117, 130, 151, 12, 46, 105, 94, 0, 70, 145, 75, 47, 58, 46, 82, 197, 172, 150, 28, 33, 106, 28, 162, 138, 135, 111, 46, 225, 95, 239, 4, 134, 222, 56, 181, 216, 47, 241, 14, 205, 234, 130, 220, 184, 130, 219, 83, 251, 128, 95, 189, 95, 23, 201, 206, 148, 195, 7, 172, 188, 142, 84, 32, 103, 92, 18, 194, 173, 70, 168, 73, 125, 65, 245, 176, 94, 118, 173, 190, 210, 102, 195, 93, 230, 116, 200, 37, 0, 11, 206, 131, 204, 55, 64, 1, 70, 48, 228, 26, 250, 183, 67, 94, 13, 49, 94, 162, 192, 74, 53, 183, 131, 205, 45, 51, 247, 33, 222, 249, 215, 6, 69, 74, 4, 9, 124, 4, 83, 240, 215, 48, 97, 140, 255, 178, 192, 69, 117, 248, 79, 207, 211, 113, 66, 66, 123, 20, 178, 217, 83, 84, 191, 231, 162, 136, 28, 122, 175, 45, 140, 114, 92, 196, 223, 111, 155, 1, 105, 155, 123, 211, 180, 141, 74, 62, 43, 216, 132, 209, 179, 115, 71, 208, 102, 176, 246, 57, 255, 42, 127, 36, 48, 111, 159, 167, 33, 199, 234, 173, 12, 175, 8, 185, 146, 118, 220, 196, 137, 22, 98, 85, 213, 235, 196, 219, 162, 162, 34, 29, 134, 213, 207, 37, 0, 0, 0, 0, 0, 1, 144, 91, 199, 32, 201, 33, 250, 79, 217, 121, 167, 76, 89, 184, 118, 237, 153, 74, 255, 88, 88, 56, 58, 110, 100, 50, 83, 200, 98, 55, 87, 200, 122, 35, 122, 127, 230, 255, 207, 241, 66, 13, 233, 175, 38, 247, 90, 27, 123, 210, 234, 202, 216, 233, 100, 227, 199, 119, 164, 36, 251, 86, 189, 137, 149, 1, 166, 183, 155, 59, 195, 124, 211, 144, 109, 9, 179, 68, 60, 36, 180, 62, 65, 198, 146, 50, 181, 229, 25, 67, 74, 74, 230, 231, 1, 19, 47, 7, 92, 202, 144, 86, 49, 224, 170, 148, 73, 128, 211, 19, 108, 155, 209, 64, 216, 187, 223, 74, 228, 248, 238, 189, 20, 60, 153, 94, 95, 82, 15, 13, 219, 6, 243, 18, 84, 127, 240, 125, 140, 121, 110, 176, 214, 16, 110, 87, 106, 71, 246, 169, 206, 98, 8, 67, 130, 188, 120, 0, 111, 203, 138, 45, 165, 2, 141, 75, 6, 90, 177, 201, 58, 72, 18, 38, 126, 59, 127, 45, 50, 0, 88, 73, 8, 194, 221, 79, 73, 120, 141, 7, 52, 53, 246, 43, 42, 136, 207, 190, 91, 189, 183, 156, 249, 198, 180, 148, 204, 191, 230, 235, 99, 215, 199, 44, 228, 222, 227, 122, 187, 219, 239, 225, 48, 147, 71, 4, 234, 126, 77, 193, 246, 113, 96, 158, 69, 210, 219, 172, 66, 226, 97, 197, 243, 210, 245, 43, 230, 166, 148, 53, 38, 242, 6, 185, 240, 178, 153, 36, 171, 251, 215, 43, 82, 190, 201, 78, 162, 64, 11, 166, 211, 188, 78, 97, 75, 250, 160, 37, 88, 224, 141, 7, 107, 171, 118, 238, 193, 234, 185, 47, 139, 132, 242, 79, 229, 208, 6, 215, 150, 6, 206, 94, 82, 225, 201, 55, 117, 216, 97, 5, 124, 14, 32, 62, 32, 169, 239, 6, 11, 32, 208, 42, 159, 4, 90, 46, 88, 92, 112, 68, 101, 206, 225, 209, 61, 105, 150, 25, 243, 56, 98, 36, 71, 212, 136, 37, 168, 86, 168, 0, 200, 111, 102, 30, 216, 117, 7, 184, 229, 148, 246, 70, 4, 36, 150, 45, 203, 214, 223, 7, 176, 124, 91, 189, 38, 69, 255, 121, 220, 171, 17, 12, 201, 165, 148, 42, 36, 226, 64, 188, 232, 149, 129, 182, 196, 211, 231, 112, 219, 199, 180, 251, 25, 127, 201, 40, 50, 209, 35, 187, 244, 8, 253, 13, 58, 51, 215, 213, 93, 71, 155, 162, 60, 183, 10, 131, 150, 2, 34, 136, 195, 216, 59, 27, 79, 87, 61, 89, 196, 35, 157, 2, 97, 87, 124, 159, 21, 95, 253, 12, 0, 0, 0, 0, 0, 0, 105, 182, 23, 96, 17, 103, 176, 147, 43, 209, 155, 7, 149, 215, 90, 134, 209, 131, 172, 52, 19, 26, 117, 71, 210, 234, 63, 244, 100, 146, 139, 29, 57, 3, 221, 173, 201, 105, 255, 91, 18, 20, 178, 71, 164, 82, 3, 211, 137, 32, 124, 162, 239, 183, 118, 201, 239, 119, 192, 146, 5, 249, 42, 106, 95, 29, 83, 22, 49, 19, 125, 238, 144, 154, 253, 204, 175, 245, 207, 244, 25, 67, 78, 11, 63, 138, 99, 211, 244, 208, 200, 167, 55, 183, 46, 253, 20, 22, 58, 164, 242, 50, 161, 145, 13, 223, 130, 26, 151, 204, 40, 6, 222, 125, 35, 108, 194, 106, 55, 248, 227, 174, 141, 91, 61, 178, 4, 197, 203, 14, 104, 98, 60, 111, 231, 221, 138, 98, 111, 223, 18, 56, 73, 139, 132, 18, 99, 4, 70, 92, 221, 81, 89, 221, 31, 149, 228, 72, 177, 231, 162, 1, 143, 229, 94, 110, 70, 182, 186, 28, 107, 157, 66, 214, 14, 174, 195, 93, 201, 170, 217, 86, 51, 114, 203, 28, 109, 123, 221, 192, 188, 101, 220, 0, 136, 209, 19, 234, 172, 136, 44, 218, 91, 143, 112, 74, 1, 232, 255, 61, 51, 21, 156, 175, 150, 15, 226, 86, 180, 132, 105, 134, 156, 62, 115, 34, 242, 103, 165, 107, 215, 182, 237, 110, 206, 251, 23, 252, 60, 116, 14, 246, 197, 142, 32, 197, 163, 248, 117, 251, 118, 175, 241, 83, 30, 60, 122, 5, 8, 4, 208, 46, 145, 180, 75, 249, 160, 172, 167, 56, 154, 209, 154, 58, 68, 106, 57, 195, 63, 189, 129, 192, 141, 56, 241, 228, 20, 111, 2, 15, 35, 102, 36, 97, 79, 46, 161, 210, 136, 100, 218, 105, 44, 53, 253, 221, 227, 239, 112, 219, 32, 11, 16, 207, 47, 62, 150, 15, 60, 50, 43, 14, 182, 155, 173, 140, 104, 227, 180, 144, 89, 200, 228, 254, 193, 196, 35, 167, 199, 133, 224, 250, 242, 125, 159, 249, 79, 138, 184, 113, 152, 93, 63, 37, 197, 185, 91, 25, 235, 195, 56, 227, 172, 245, 67, 154, 20, 118, 95, 228, 170, 115, 81, 112, 150, 5, 109, 240, 219, 70, 185, 156, 109, 202, 187, 3, 56, 121, 194, 103, 163, 220, 195, 194, 178, 85, 188, 116, 211, 58, 208, 200, 151, 61, 54, 144, 202, 62, 172, 67, 176, 226, 186, 183, 177, 12, 37, 237, 3, 118, 201, 63, 2, 168, 126, 57, 46, 1, 95, 18, 174, 220, 232, 113, 228, 181, 42, 83, 197, 182, 71, 246, 6, 236, 115, 211, 177, 216, 197, 38, 0, 0, 0, 0, 0, 0, 2, 89, 189, 144, 235, 204, 167, 169, 168, 38, 73, 206, 68, 197, 88, 229, 37, 140, 130, 136, 209, 243, 101, 106, 236, 47, 90, 144, 178, 14, 58, 61, 188, 17, 231, 108, 82, 230, 147, 59, 123, 231, 31, 236, 57, 152, 178, 187, 190, 73, 58, 106, 197, 255, 20, 209, 100, 96, 89, 43, 25, 74, 62, 189, 188, 10, 141, 136, 177, 57, 230, 164, 235, 5, 26, 236, 35, 39, 235, 12, 13, 232, 115, 234, 135, 159, 9, 63, 44, 64, 119, 124, 11, 25, 62, 181, 112, 1, 165, 113, 86, 130, 154, 71, 110, 155, 140, 210, 40, 114, 246, 29, 145, 131, 53, 145, 137, 116, 162, 207, 133, 194, 213, 4, 30, 202, 3, 24, 163, 37, 98, 161, 183, 219, 52, 222, 8, 86, 98, 36, 60, 99, 31, 170, 249, 62, 129, 195, 77, 38, 250, 225, 42, 210, 78, 125, 80, 166, 198, 174, 173, 41, 195, 47, 66, 55, 9, 230, 51, 30, 83, 150, 123, 81, 9, 189, 234, 174, 163, 147, 23, 224, 125, 36, 178, 238, 247, 174, 77, 80, 35, 146, 140, 29, 170, 29, 13, 118, 154, 71, 130, 24, 177, 113, 24, 9, 132, 112, 72, 200, 157, 91, 33, 134, 62, 69, 30, 87, 228, 124, 56, 83, 163, 104, 218, 46, 215, 28, 233, 160, 69, 59, 178, 226, 17, 110, 125, 2, 182, 16, 51, 35, 148, 248, 78, 159, 29, 186, 68, 167, 191, 2, 183, 134, 108, 180, 130, 41, 85, 103, 179, 188, 87, 122, 249, 218, 106, 177, 188, 208, 24, 108, 242, 177, 55, 92, 123, 139, 176, 61, 139, 79, 148, 85, 160, 145, 179, 236, 144, 40, 47, 132, 244, 230, 31, 192, 174, 93, 184, 180, 48, 126, 222, 121, 238, 199, 253, 153, 19, 208, 202, 236, 239, 153, 252, 108, 48, 125, 133, 14, 136, 25, 90, 194, 6, 228, 182, 150, 53, 103, 62, 155, 172, 92, 206, 141, 12, 45, 226, 36, 4, 58, 228, 53, 13, 68, 0, 65, 81, 31, 159, 195, 111, 21, 245, 150, 32, 247, 60, 235, 46, 214, 148, 144, 135, 82, 26, 147, 102, 246, 25, 189, 181, 13, 211, 192, 42, 144, 52, 165, 201, 215, 185, 85, 61, 37, 186, 201, 189, 210, 75, 145, 128, 244, 94, 215, 198, 15, 212, 94, 134, 79, 105, 228, 88, 3, 126, 242, 193, 194, 171, 219, 194, 164, 29, 36, 82, 36, 0, 0, 0, 0, 0, 0, 1, 122}

	transcript := [2312]uints.U8{}
	for i := range transcriptBytes {
		transcript[i] = uints.NewU8(transcriptBytes[i])
	}

	assignment := WhirCircuit{
		IO:         []byte(ioPat),
		Transcript: transcript,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	vErr := groth16.Verify(proof, vk, publicWitness)
	fmt.Printf("%v\n", vErr)
}

type Manhattan struct {
	I, O frontend.Variable
}

func (c *Manhattan) Define(api frontend.API) error {
	s := hash.NewSkyscraper(api)
	a := c.I
	for range 3000 {
		a = s.Compress(a, a)
	}
	api.AssertIsEqual(c.O, a)
	return nil
}

func ExampleManhattan() {

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Manhattan{})
	if err != nil {
		fmt.Println(err)
		return
	}
	pk, vk, _ := groth16.Setup(ccs)
	assignment := Manhattan{
		I: 1,
		O: 1000,
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	vErr := groth16.Verify(proof, vk, publicWitness)
	fmt.Printf("%v\n", vErr)
}

type TestLookup struct {
	In frontend.Variable
}

func (c *TestLookup) Define(api frontend.API) error {
	table := logderivlookup.New(api)
	for i := range 256 {
		table.Insert(bits.RotateLeft8(uint8(i), 3))
	}
	c0 := c.In
	for range 256 {
		c0 = table.Lookup(c0)[0]
	}
	api.AssertIsEqual(c0, c.In)
	return nil
}

func main() {
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &TestLookup{})
	fmt.Printf("constraints: %d\n", ccs.GetNbConstraints())

	//Example1()
	//ExampleWhir()
	//ExampleManhattan()
}
