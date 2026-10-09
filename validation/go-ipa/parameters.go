package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/crate-crypto/go-ipa/banderwagon"
	"github.com/crate-crypto/go-ipa/ipa"
	"os"
	"regexp"
)

// Check all Rust embedded CRS points through Go's independent decoder and compare
// canonical compressed encodings with the newly generated Go CRS. Rust stores
// affine coordinates little-endian; Go's trusted affine decoder uses big-endian.
func parameters(c *ipa.IPAConfig, path string) {
	source, err := os.ReadFile(path)
	must(err)
	raw := regexp.MustCompile(`"([0-9a-f]{128})"`).FindAllSubmatch(source, -1)
	if len(raw) != 257 {
		panic("expected 256 G points and Q")
	}
	digest := sha256.New()
	for i, row := range raw {
		b, err := hex.DecodeString(string(row[1]))
		must(err)
		for off := 0; off < 64; off += 32 {
			for j := 0; j < 16; j++ {
				b[off+j], b[off+31-j] = b[off+31-j], b[off+j]
			}
		}
		var rust banderwagon.Element
		must(rust.SetBytesUncompressed(b, true))
		goPoint := c.Q
		if i < 256 {
			goPoint = c.SRS[i]
		}
		rb, gb := rust.Bytes(), goPoint.Bytes()
		if rb != gb {
			panic(fmt.Sprintf("CRS mismatch at %d", i))
		}
		digest.Write(gb[:])
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"crs_points": 257, "compressed_crs_sha256": hex.EncodeToString(digest.Sum(nil)), "rust_source": path}))
}
