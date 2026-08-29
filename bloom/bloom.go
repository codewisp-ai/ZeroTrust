package bloom

import (
	"hash/fnv"
	"math"
	"sync"
)

// Filter is a thread-safe hand-rolled Bloom filter utilizing FNV-1/FNV-1a double hashing.
type Filter struct {
	mu    sync.RWMutex
	bits  []uint64
	m     uint64 // total bit size
	k     uint64 // number of hash functions
	count uint64 // number of inserted items
}

// New creates a new Bloom filter sized for expectedEntries and falsePositiveRate.
func New(expectedEntries int, falsePositiveRate float64) *Filter {
	if expectedEntries <= 0 {
		expectedEntries = 1000
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = 0.01
	}

	n := float64(expectedEntries)
	m := math.Ceil(-n * math.Log(falsePositiveRate) / (math.Pow(math.Log(2), 2)))
	k := math.Round((m / n) * math.Log(2))

	bitSize := uint64(m)
	if bitSize < 64 {
		bitSize = 64
	}

	numWords := (bitSize + 63) / 64

	return &Filter{
		bits: make([]uint64, numWords),
		m:    numWords * 64,
		k:    uint64(k),
	}
}

// Add inserts a string into the Bloom filter.
func (f *Filter) Add(item string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	h1, h2 := f.hash(item)
	for i := uint64(0); i < f.k; i++ {
		idx := (h1 + i*h2) % f.m
		f.bits[idx/64] |= (1 << (idx % 64))
	}
	f.count++
}

// Contains checks if a string might be in the Bloom filter.
func (f *Filter) Contains(item string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	h1, h2 := f.hash(item)
	for i := uint64(0); i < f.k; i++ {
		idx := (h1 + i*h2) % f.m
		if (f.bits[idx/64] & (1 << (idx % 64))) == 0 {
			return false
		}
	}
	return true
}

func (f *Filter) hash(item string) (uint64, uint64) {
	hasher1 := fnv.New64()
	hasher1.Write([]byte(item))
	h1 := hasher1.Sum64()

	hasher2 := fnv.New64a()
	hasher2.Write([]byte(item))
	h2 := hasher2.Sum64()

	// Ensure h2 is odd so it is coprime to 2^N powers
	if h2%2 == 0 {
		h2++
	}

	return h1, h2
}
