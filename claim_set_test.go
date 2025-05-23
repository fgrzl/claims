package claims

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClaimsSet(t *testing.T) {
	cs := NewClaimsSet("foo", "bar")
	require.Len(t, cs, 1)
	require.Equal(t, "bar", cs["foo"].Value())
}

func TestClaimSetSet(t *testing.T) {
	cs := NewClaimsSet("foo", "bar")
	cs2 := cs.Set("baz", "qux")

	require.Len(t, cs, 1)  // original unchanged
	require.Len(t, cs2, 2) // new one has both
	require.Equal(t, "bar", cs2["foo"].Value())
	require.Equal(t, "qux", cs2["baz"].Value())
}

func TestToClaimList(t *testing.T) {
	cs := NewClaimsSet("a", "1").Set("b", "2")
	list := cs.ToClaimList()

	require.Len(t, list, 2)
	names := map[string]bool{}
	for _, c := range list {
		names[c.Name()] = true
	}
	require.True(t, names["a"])
	require.True(t, names["b"])
}

func TestClaimSetJSONRoundTrip(t *testing.T) {
	original := NewClaimsSet("x", "123").Set("y", "456")

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded ClaimSet
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, original["x"].Value(), decoded["x"].Value())
	require.Equal(t, original["y"].Value(), decoded["y"].Value())
}
