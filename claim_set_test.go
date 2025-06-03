package claims

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClaimsSet(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")

	require.Equal(t, "tester", (cs.state)[sub].Value())
	require.Equal(t, "bar", (cs.state)["foo"].Value())
}

func TestClaimSetSet(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")
	cs.Set("baz", "qux") // same instance is mutated

	require.Equal(t, "bar", (cs.state)["foo"].Value())
	require.Equal(t, "qux", (cs.state)["baz"].Value())
}

func TestToClaimList(t *testing.T) {
	cs := NewClaimsSet("tester").Set("a", "1").Set("b", "2")
	list := cs.ToClaimList()

	names := map[string]bool{}
	for _, c := range list {
		names[c.Name()] = true
	}
	require.True(t, names["a"])
	require.True(t, names["b"])
}
