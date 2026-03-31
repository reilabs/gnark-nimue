package hash

import (
	"github.com/consensys/gnark/frontend"
	skyscraper "github.com/reilabs/gnark-skyscraper"
	"math/big"
	"slices"
)

type SkyscraperState struct {
	skyscraper *skyscraper.Skyscraper
	s          [2]frontend.Variable
}

func (s *SkyscraperState) N() int {
	return 2
}

func (s *SkyscraperState) R() int {
	return 1
}

func (s *SkyscraperState) Initialize(iv [32]byte) {
	slices.Reverse(iv[:])
	felt := new(big.Int).SetBytes(iv[:])
	s.s[0] = 0
	s.s[1] = felt
}

func (s *SkyscraperState) Permute() {
	s.skyscraper.PermuteV2(&s.s)
}

func (s *SkyscraperState) State() []frontend.Variable {
	return s.s[:]
}

func (s *SkyscraperState) Zeroize(index int) {
	s.s[index] = 0
}

func (s *SkyscraperState) PrintState(api frontend.API) {
	api.Println(s.s[:]...)
}

type Skyscraper DuplexHash[frontend.Variable]

func NewSkyScraper(sc *skyscraper.Skyscraper) (Skyscraper, error) {
	return &DuplexSponge[frontend.Variable, *SkyscraperState]{
		sponge: &SkyscraperState{
			skyscraper: sc,
			s:          [2]frontend.Variable{0, 0},
		},
	}, nil
}
