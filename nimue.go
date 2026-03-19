package gnark_nimue

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	bits2 "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reilabs/gnark-nimue/hash"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// 2^256 mod BN254 scalar field modulus, precomputed for combining two 32-byte
// squeezes into a single challenge scalar with statistical uniformity.
var twoPow256ModP = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), ecc.BN254.ScalarField())

type Nimue interface {
	FillNextBytes(uints []uints.U8) error
	FillChallengeBytes(uints []uints.U8) error
	FillNextScalars(scalars []frontend.Variable) error
	FillChallengeScalars(scalars []frontend.Variable) error
	PrintState(api frontend.API)
}

type byteNimue[H hash.DuplexHash[uints.U8]] struct {
	api        frontend.API
	transcript []uints.U8
	safe       *Safe[uints.U8, H]
}

func NewByteNimue[S hash.DuplexHash[uints.U8]](api frontend.API, transcript []uints.U8, hash S) Nimue {
	safe := NewSafe(hash)
	return &byteNimue[S]{
		api,
		transcript,
		safe,
	}
}

func NewKeccakNimue(api frontend.API, transcript []uints.U8) (Nimue, error) {
	sponge, err := hash.NewKeccak(api)
	if err != nil {
		return nil, err
	}
	return NewByteNimue(api, transcript, sponge), nil
}

func (nimue *byteNimue[H]) FillNextBytes(uints []uints.U8) error {
	copy(uints, nimue.transcript)
	nimue.transcript = nimue.transcript[len(uints):]
	nimue.safe.Absorb(uints)
	return nil
}

func (nimue *byteNimue[H]) FillChallengeBytes(uints []uints.U8) error {
	nimue.safe.Squeeze(uints)
	return nil
}

func (nimue *byteNimue[H]) FillNextScalars(scalars []frontend.Variable) error {
	bytesToRead := (nimue.api.Compiler().FieldBitLen() + 7) / 8
	bytes := make([]uints.U8, bytesToRead)
	for i := range scalars {
		scalars[i] = frontend.Variable(0)
		err := nimue.FillNextBytes(bytes)
		if err != nil {
			return err
		}
		curMul := big.NewInt(1)
		for _, b := range bytes {
			scalars[i] = nimue.api.Add(scalars[i], nimue.api.Mul(b.Val, curMul))
			curMul.Mul(curMul, big.NewInt(256))
		}
	}
	return nil
}

func (nimue *byteNimue[H]) FillChallengeScalars(scalars []frontend.Variable) error {
	bytesToGenerate := (nimue.api.Compiler().FieldBitLen() + 128) / 8
	bytes := make([]uints.U8, bytesToGenerate)
	for i := range scalars {
		err := nimue.FillChallengeBytes(bytes)
		if err != nil {
			return err
		}
		scalars[i] = frontend.Variable(0)
		for _, b := range bytes {
			scalars[i] = nimue.api.Add(b.Val, nimue.api.Mul(scalars[i], 256))
		}
	}
	return nil
}

func (nimue *byteNimue[H]) PrintState(api frontend.API) {
	msg := fmt.Sprintf("remaining transcript bytes: %d", len(nimue.transcript))
	api.Println(msg)
	nimue.safe.sponge.PrintState(api)
}

type nativeNimue[H hash.DuplexHash[frontend.Variable]] struct {
	api        frontend.API
	transcript []uints.U8
	safe       *Safe[frontend.Variable, H]
}

func (nimue *nativeNimue[H]) FillNextBytes(uints []uints.U8) error {
	copy(uints, nimue.transcript)
	nimue.transcript = nimue.transcript[len(uints):]
	// Pack bytes into LE field elements (32 bytes per element) to match the
	// native byte-level sponge which packs multiple bytes into each rate slot.
	for i := 0; i < len(uints); i += 32 {
		end := min(i+32, len(uints))
		fe := frontend.Variable(0)
		curMul := big.NewInt(1)
		for _, b := range uints[i:end] {
			fe = nimue.api.Add(fe, nimue.api.Mul(b.Val, curMul))
			curMul = new(big.Int).Mul(curMul, big.NewInt(256))
		}
		nimue.safe.Absorb([]frontend.Variable{fe})
	}
	return nil
}

func (nimue *nativeNimue[H]) FillChallengeBytes(out []uints.U8) error {
	if len(out) == 0 {
		return nil
	}
	tmp := make([]frontend.Variable, 1)
	for i := 0; i < len(out); {
		nimue.safe.Squeeze(tmp)
		// Decompose field element to LE bytes. BN254 scalars fit in 254 bits;
		// pad to 256 (32 bytes) with two trailing zero bits.
		allBits := bits2.ToBinary(nimue.api, tmp[0])
		for len(allBits) < 256 {
			allBits = append(allBits, frontend.Variable(0))
		}
		for k := range 32 {
			if i >= len(out) {
				break
			}
			out[i] = uints.NewU8(0)
			curMul := 1
			for j := range 8 {
				out[i].Val = nimue.api.Add(nimue.api.Mul(curMul, allBits[8*k+j]), out[i].Val)
				curMul *= 2
			}
			i++
		}
	}
	return nil
}

func (nimue *nativeNimue[H]) FillNextScalars(out []frontend.Variable) error {
	wordSize := (nimue.api.Compiler().FieldBitLen() + 7) / 8
	for i := range out {
		bytes := nimue.transcript[:wordSize]
		nimue.transcript = nimue.transcript[wordSize:]
		out[i] = frontend.Variable(0)
		curMul := big.NewInt(1)
		for _, b := range bytes {
			out[i] = nimue.api.Add(out[i], nimue.api.Mul(b.Val, curMul))
			curMul.Mul(curMul, big.NewInt(256))
		}
	}
	nimue.safe.Absorb(out)
	return nil
}

func (nimue *nativeNimue[H]) FillChallengeScalars(out []frontend.Variable) error {
	// Squeeze 2 field elements per challenge to match spongefish's DecodingFieldBuffer
	// which uses (MODULUS_BIT_SIZE.div_ceil(8) + 32) = 64 bytes per challenge for
	// statistical uniformity, then reduces mod p.
	tmp := make([]frontend.Variable, 2)
	for i := range out {
		nimue.safe.Squeeze(tmp)
		lo := tmp[0]
		hi := tmp[1]
		// combined = lo + hi * 2^256 (mod p, implicit in gnark field arithmetic)
		out[i] = nimue.api.Add(lo, nimue.api.Mul(hi, twoPow256ModP))
	}
	return nil
}

func (nimue *nativeNimue[H]) PrintState(api frontend.API) {
	nimue.safe.sponge.PrintState(api)
}

// NimueInit holds the protocol_id (as two field elements: low 32 bytes,
// high 32 bytes) and session_id (one field element, 32 bytes) used to initialize
// the sponge before any transcript operations.
type NimueInit struct {
	ProtocolID [2]frontend.Variable
	SessionID  frontend.Variable
}

// NewSkyscraperNimue creates an Nimue whose sponge is initialized by absorbing
// the provided ProtocolID and SessionID field elements.
func NewSkyscraperNimue(api frontend.API, sc *skyscraper.Skyscraper, init NimueInit, transcript []uints.U8) (Nimue, error) {
	sponge, err := hash.NewSkyScraper(sc)
	if err != nil {
		return nil, err
	}
	safe := NewSafe(sponge)
	safe.Absorb([]frontend.Variable{init.ProtocolID[0], init.ProtocolID[1], init.SessionID})
	return &nativeNimue[hash.Skyscraper]{api, transcript, safe}, nil
}
