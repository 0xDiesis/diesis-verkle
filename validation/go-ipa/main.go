// Deterministic runtime comparison with the pinned upstream Go implementation.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mp "github.com/crate-crypto/go-ipa"
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/crate-crypto/go-ipa/banderwagon"
	"github.com/crate-crypto/go-ipa/common"
	"github.com/crate-crypto/go-ipa/ipa"
	"os"
)

type record struct {
	N           int    `json:"n"`
	Mode        string `json:"mode"`
	Proof       string `json:"proof"`
	Commitments string `json:"commitments"`
	D           string `json:"d"`
	E           string `json:"e"`
	Challenge   string `json:"challenge"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hx(b [32]byte) string { return hex.EncodeToString(b[:]) }
func setup(c *ipa.IPAConfig, n int, mode string) ([]*banderwagon.Element, [][]fr.Element, []uint8, []*fr.Element) {
	cs := make([]*banderwagon.Element, n)
	fs := make([][]fr.Element, n)
	zs := make([]uint8, n)
	ys := make([]*fr.Element, n)
	for i := 0; i < n; i++ {
		id := i + 1
		if mode == "repeated" {
			id = i%4 + 1
		}
		if mode == "identity" {
			id = 0
		}
		f := make([]fr.Element, 256)
		for j := range f {
			if id != 0 {
				f[j].SetUint64(uint64(id*1009 + (j+1)*(j+3) + 17))
			}
		}
		z := uint8((i * 73) % 256)
		if i%4 == 0 {
			z = 0
		}
		if i%4 == 1 {
			z = 255
		}
		fs[i] = f
		zs[i] = z
		ys[i] = &f[z]
		cc := c.Commit(f)
		cs[i] = &cc
	}
	return cs, fs, zs, ys
}
func verify(c *ipa.IPAConfig, p *mp.MultiProof, cs []*banderwagon.Element, ys []*fr.Element, zs []uint8) bool {
	ok, err := mp.CheckMultiProof(common.NewTranscript("diesis-crosscheck-v1"), c, p, cs, ys, zs)
	return err == nil && ok
}
func main() {
	c, err := ipa.NewIPASettings()
	must(err)
	if len(os.Args) == 3 && os.Args[1] == "--parameters" {
		parameters(c, os.Args[2])
		return
	}
	peers := map[string]record{}
	if len(os.Args) > 1 {
		f, e := os.Open(os.Args[1])
		must(e)
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 65536), 1<<22)
		for s.Scan() {
			var r record
			must(json.Unmarshal(s.Bytes(), &r))
			peers[fmt.Sprint(r.N, "/", r.Mode)] = r
		}
		must(s.Err())
	}
	enc := json.NewEncoder(os.Stdout)
	for _, n := range []int{1, 16, 256, 1024} {
		for _, mode := range []string{"distinct", "repeated", "identity"} {
			cs, fs, zs, ys := setup(c, n, mode)
			tr := common.NewTranscript("diesis-crosscheck-v1")
			p, e := mp.CreateMultiProof(tr, c, cs, fs, zs)
			must(e)
			if !verify(c, p, cs, ys, zs) {
				panic("self verify")
			}
			var out bytes.Buffer
			must(p.Write(&out))
			after := tr.ChallengeScalar([]byte("crosscheck-after"))
			r := record{N: n, Mode: mode, Proof: hex.EncodeToString(out.Bytes()), D: hx(p.D.Bytes()), Challenge: hx(after.BytesLE())}
			audit := common.NewTranscript("diesis-crosscheck-v1")
			audit.DomainSep([]byte("multiproof"))
			for i := range cs {
				r.Commitments += hx(cs[i].Bytes())
				audit.AppendPoint(cs[i], []byte("C"))
				var z fr.Element
				z.SetUint64(uint64(zs[i]))
				audit.AppendScalar(&z, []byte("z"))
				audit.AppendScalar(ys[i], []byte("y"))
			}
			rr := audit.ChallengeScalar([]byte("r"))
			audit.AppendPoint(&p.D, []byte("D"))
			tt := audit.ChallengeScalar([]byte("t"))
			power := fr.One()
			h := make([]fr.Element, 256)
			for i := range fs {
				var z, den, weight fr.Element
				z.SetUint64(uint64(zs[i]))
				den.Sub(&tt, &z)
				den.Inverse(&den)
				weight.Mul(&power, &den)
				for j := range h {
					var x fr.Element
					x.Mul(&fs[i][j], &weight)
					h[j].Add(&h[j], &x)
				}
				power.Mul(&power, &rr)
			}
			ee := c.Commit(h)
			r.E = hx(ee.Bytes())
			if peer, ok := peers[fmt.Sprint(n, "/", mode)]; ok {
				if peer != r {
					panic(fmt.Sprintf("Rust/Go record mismatch n=%d mode=%s", n, mode))
				}
				b, e := hex.DecodeString(peer.Proof)
				must(e)
				var pp mp.MultiProof
				must(pp.Read(bytes.NewReader(b)))
				if !verify(c, &pp, cs, ys, zs) {
					panic("Rust proof rejected by Go")
				}
			}
			old := *ys[0]
			one := fr.One()
			ys[0].Add(ys[0], &one)
			if verify(c, p, cs, ys, zs) {
				panic("tampered result accepted")
			}
			*ys[0] = old
			orig := zs[0]
			zs[0] ^= 1
			if mode != "identity" && verify(c, p, cs, ys, zs) {
				panic("tampered point accepted")
			}
			zs[0] = orig
			stale := *cs[0]
			cs[0] = &c.SRS[0]
			if verify(c, p, cs, ys, zs) {
				panic("stale commitment accepted")
			}
			cs[0] = &stale
			oldD := p.D
			p.D = c.SRS[1]
			if verify(c, p, cs, ys, zs) {
				panic("tampered proof accepted")
			}
			p.D = oldD
			must(enc.Encode(r))
			fmt.Fprintf(os.Stderr, "Go passed n=%d mode=%s reciprocal=%t\n", n, mode, len(peers) > 0)
		}
	}
	if len(peers) > 0 && len(peers) != 12 {
		panic("incomplete peer batch")
	}
}
