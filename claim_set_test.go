package claims

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClaimsSet(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")

	require.Len(t, cs, 2)
	require.Equal(t, "tester", (cs)[sub].Value())
	require.Equal(t, "bar", (cs)["foo"].Value())
}

func TestClaimSetSet(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")
	cs.Set("baz", "qux") // same instance is mutated

	require.Len(t, cs, 3)
	require.Equal(t, "bar", (cs)["foo"].Value())
	require.Equal(t, "qux", (cs)["baz"].Value())
}

func TestToClaimList(t *testing.T) {
	cs := NewClaimsSet("tester").Set("a", "1").Set("b", "2")
	list := cs.ToClaimList()

	require.Len(t, list, 3)
	names := map[string]bool{}
	for _, c := range list {
		names[c.Name()] = true
	}
	require.True(t, names["a"])
	require.True(t, names["b"])
}
