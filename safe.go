package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-nimue/hash"
)

type Safe[U any, H hash.DuplexHash[U]] struct {
	sponge H
}

func NewSafe[U any, H hash.DuplexHash[U]](sponge H) *Safe[U, H] {
	return &Safe[U, H]{
		sponge: sponge,
	}
}

func (safe *Safe[U, H]) Squeeze(out []U) {
	safe.sponge.Squeeze(out)
}

func (safe *Safe[U, H]) Absorb(in []U) {
	safe.sponge.Absorb(in)
}

func (safe *Safe[U, H]) PrintState(api frontend.API) {
	safe.sponge.PrintState(api)
}
