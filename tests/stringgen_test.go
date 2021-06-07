package tests

import (
	"pwman/util"
	"testing"
)

func TestStringGeneration(t *testing.T) {
	_, e := util.GenerateCryptoString(0)

	if e == nil {
		t.Fatalf("Function did not throw error on invalid length arg")
	}

	a, _ := util.GenerateCryptoString(10)

	if len(a) != 10 {
		t.Fatalf("Generated strings were not of the specified length.")
	}

	b, _ := util.GenerateCryptoString(10)
	c, _ := util.GenerateCryptoString(10)

	if a == b && b == c && a == c {
		t.Fatalf("All three generated strings were the same")
	}

	t.Logf("Generated strings: %v, %v, %v", a, b, c)
}
