package tests

import (
	"fmt"
	"testing"

	"zerotrust/bloom"
)

func TestBloomFilterBasic(t *testing.T) {
	bf := bloom.New(100, 0.01)

	items := []string{"express", "lodash", "requests", "serde", "tokio"}
	for _, item := range items {
		bf.Add(item)
	}

	for _, item := range items {
		if !bf.Contains(item) {
			t.Errorf("Bloom filter failed to contain inserted item: %s", item)
		}
	}

	nonExistent := []string{"nonexistent-pkg-xyz-123", "fake-slop-squat-999"}
	for _, item := range nonExistent {
		if bf.Contains(item) {
			// False positives are possible, but for 2 items in small set should be very low
			t.Logf("Notice: false positive for %s", item)
		}
	}
}

func TestBloomFilterFalsePositiveBound(t *testing.T) {
	n := 1000
	targetFP := 0.05
	bf := bloom.New(n, targetFP)

	for i := 0; i < n; i++ {
		bf.Add(fmt.Sprintf("package-%d", i))
	}

	falsePositives := 0
	testCount := 10000
	for i := 0; i < testCount; i++ {
		testKey := fmt.Sprintf("uninserted-key-%d", i)
		if bf.Contains(testKey) {
			falsePositives++
		}
	}

	actualFPRate := float64(falsePositives) / float64(testCount)
	t.Logf("Actual false positive rate: %.4f (target: %.4f)", actualFPRate, targetFP)

	if actualFPRate > targetFP*2 {
		t.Errorf("False positive rate %.4f exceeded bounds (target %.4f)", actualFPRate, targetFP)
	}
}
