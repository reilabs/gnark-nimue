package hash

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type KeccakState struct {
	uapi  *uints.BinaryField[uints.U64]
	state [200]uints.U8
}

func (k *KeccakState) N() int {
	return 200
}

func (k *KeccakState) R() int {
	return 136
}

func (k *KeccakState) Initialize(iv [32]byte) {
	for i := range 32 {
		k.state[k.R()+i] = uints.NewU8(iv[i])
	}
}

func (k *KeccakState) Permute() {
	state := [25]uints.U64{}
	for i, s := range k.state {
		state[i/8][i%8] = s
	}
	result := keccakf.Permute(k.uapi, state)
	for i, _ := range k.state {
		k.state[i] = result[i/8][i%8]
	}
}

func (k *KeccakState) State() []uints.U8 {
	return k.state[:]
}

func (k *KeccakState) Zeroize(index int) {
	k.state[index] = uints.NewU8(0)
}

func (k *KeccakState) PrintState(api frontend.API) {
	vars := make([]frontend.Variable, len(k.state))
	for i, s := range k.state {
		vars[i] = s.Val
	}
	api.Println(vars...)
}

type Keccak DuplexHash[uints.U8]

func NewKeccak(api frontend.API) (Keccak, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	state := [200]uints.U8{}
	for i := range state {
		state[i] = uints.NewU8(0)
	}
	return &DuplexSponge[uints.U8, *KeccakState]{
		sponge: &KeccakState{
			uapi:  uapi,
			state: state,
		},
		absorbPos:  0,
		squeezePos: 136,
	}, nil
}
