package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

// TestParseLinuxKernelModuleMetadata_parmAndParmtypeMerged guards the .modinfo
// contract where a parameter's description ("parm=name:description") and its type
// ("parmtype=name:type") arrive as SEPARATE entries, in either order (#5318).
// The parser used to update a copy of the map value on the second entry, so the
// parameter kept only whichever field the FIRST parsed entry carried.
func TestParseLinuxKernelModuleMetadata_parmAndParmtypeMerged(t *testing.T) {
	modinfo := []string{
		"name=fixture_mod",
		"vermagic=6.1.0 SMP mod_unload",
		// both entries for the same parameter → type AND description
		"parm=both:desc for both",
		"parmtype=both:int",
		// reversed order: parmtype first, then parm
		"parmtype=reverse:bool",
		"parm=reverse:desc for reverse",
		// description-only and type-only parameters stay single-field
		"parm=desconly:desc only",
		"parmtype=typeonly:ushort",
	}

	meta, err := parseLinuxKernelModuleMetadata(wrapUnionReader(minimalKOBytes(modinfo)))
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.Contains(t, meta.Parameters, "both")
	require.Contains(t, meta.Parameters, "reverse")
	require.Contains(t, meta.Parameters, "desconly")

	expBoth := pkg.LinuxKernelModuleParameter{Type: "int", Description: "desc for both"}
	assert.Equal(t, expBoth, meta.Parameters["both"], "parm+parmtype for the same name must merge, not overwrite")

	expReverse := pkg.LinuxKernelModuleParameter{Type: "bool", Description: "desc for reverse"}
	assert.Equal(t, expReverse, meta.Parameters["reverse"], "merge must hold in the parmtype-first order too")

	expDescOnly := pkg.LinuxKernelModuleParameter{Description: "desc only"}
	assert.Equal(t, expDescOnly, meta.Parameters["desconly"], "description-only parameter must survive")

	expTypeOnly := pkg.LinuxKernelModuleParameter{Type: "ushort"}
	assert.Equal(t, expTypeOnly, meta.Parameters["typeonly"], "type-only parameter must survive")
}
