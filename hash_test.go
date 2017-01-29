package hashbench

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"math/rand"
	"testing"

	b2 "github.com/minio/blake2b-simd"
	xb2 "golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

const inputCount = 1024 * 1024

var doNotRemove []byte

var input, output []byte

func init() {
	input = make([]byte, inputCount)
	rand.Seed(605)
	rand.Read(input)
}

func run(b *testing.B, h hash.Hash) {
	b.StopTimer()
	r := bytes.NewReader(input)
	b.SetBytes(int64(len(input)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		io.Copy(h, r)
		output = h.Sum(nil)
		r.Seek(0, 0)
		h.Reset()
	}
	b.StopTimer()
	doNotRemove = output
}

func justHash(h hash.Hash, err error) hash.Hash {
	if err != nil {
		panic(err)
	}
	return h
}

func Benchmark(b *testing.B) {
	list := []struct {
		name string
		h    hash.Hash
	}{
		{name: "crc32", h: crc32.NewIEEE()},
		{name: "crc64", h: crc64.New(crc64.MakeTable(crc64.ISO))},
		{name: "sha1", h: sha1.New()},
		{name: "sha256", h: sha256.New()},
		{name: "sha512", h: sha512.New()},
		{name: "sha3-256", h: sha3.New256()},
		{name: "sha3-512", h: sha3.New512()},
		{name: "fnv32", h: fnv.New32()},
		{name: "fnv64", h: fnv.New64()},
		{name: "adler43", h: adler32.New()},
		{name: "md5", h: md5.New()},
		{name: "blake2b-256-minio", h: b2.New256()},
		{name: "blake2b-512-minio", h: b2.New512()},
		{name: "blake2b-256-x", h: justHash(xb2.New256(nil))},
		{name: "blake2b-512-x", h: justHash(xb2.New512(nil))},
	}

	for _, item := range list {
		b.Run(item.name, func(b *testing.B) {
			run(b, item.h)
		})
	}
}

func TestBlake2b(t *testing.T) {
	r := func(h hash.Hash) []byte {
		h.Write(input)
		return h.Sum(nil)
	}
	mout := r(b2.New512())
	xout := r(justHash(xb2.New512(nil)))

	if bytes.Equal(mout, xout) == false {
		t.Fatal("not equal")
	}
	t.Logf("len out: %d", len(xout))
	t.Logf("hex out: %s", hex.EncodeToString(xout))
}
