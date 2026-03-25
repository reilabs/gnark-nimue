package hash

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
)

type Sponge[U any] interface {
	N() int
	R() int
	Initialize(iv [32]byte)
	Permute()
	State() []U
	Zeroize(index int)
	PrintState(api frontend.API)
}

type DuplexHash[U any] interface {
	Initialize(iv [32]byte)
	Absorb(data []U)
	Squeeze(out []U)
	Ratchet()
	PrintState(api frontend.API)
}

type DuplexSponge[U any, S Sponge[U]] struct {
	sponge     S
	absorbPos  int
	squeezePos int
}

func (s *DuplexSponge[U, S]) Initialize(iv [32]byte) {
	s.sponge.Initialize(iv)
	s.absorbPos = 0
	s.squeezePos = s.sponge.R()
}

func (s *DuplexSponge[U, S]) Absorb(input []U) {
	s.squeezePos = s.sponge.R()

	for len(input) > 0 {
		if s.absorbPos == s.sponge.R() {
			s.sponge.Permute()
			s.absorbPos = 0
		} else {
			chunkLen := min(len(input), s.sponge.R()-s.absorbPos)
			chunk, rest := input[:chunkLen], input[chunkLen:]
			copy(s.sponge.State()[s.absorbPos:], chunk)
			s.absorbPos += chunkLen
			input = rest
		}
	}
}

func (s *DuplexSponge[U, S]) Squeeze(output []U) {
	if len(output) == 0 {
		return
	}

	if s.squeezePos == s.sponge.R() {
		s.squeezePos = 0
		s.absorbPos = 0
		s.sponge.Permute()
	}

	chunkLen := min(len(output), s.sponge.R()-s.squeezePos)
	output, rest := output[:chunkLen], output[chunkLen:]
	copy(output, s.sponge.State()[s.squeezePos:])
	s.squeezePos += chunkLen
	s.Squeeze(rest)
}

func (s *DuplexSponge[U, S]) Ratchet() {
	for i := range s.sponge.R() {
		s.sponge.Zeroize(i)
	}
	s.sponge.Permute()
	s.absorbPos = 0
	s.squeezePos = s.sponge.R()
}

func (s *DuplexSponge[U, S]) PrintState(api frontend.API) {
	msg := fmt.Sprintf("absorbPos %d squeezePos %d", s.absorbPos, s.squeezePos)
	api.Println(msg)
	s.sponge.PrintState(api)
}
