package bgptest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicy(t *testing.T) {
	rustyImage := rustyImageName()
	fmt.Println("rusty image name ", rustyImage)
	gobgpImage := gobgpImageName()
	fmt.Println("gobgp image name ", gobgpImage)

	c, err := newBgpTest()
	assert.Nil(t, err)
	err = c.createPeer("r1", rustyImage, 65000)
	assert.Nil(t, err)
	err = c.createPeer("g1", gobgpImage, 65100)
	assert.Nil(t, err)

	c.addAsDefinedSet("r1", "asset1", "_65100_")
	c.addAsDefinedSet("g1", "asset1", "^65100_")

	c.addAsDefinedSet("r1", "asset2", "_65100$")
	c.addAsDefinedSet("g1", "asset2", "_65100$")

	c.addStatement("r1", "s1", "asset1")
	c.addStatement("r1", "s2", "asset2")
	c.addStatement("g1", "s1", "asset1")
	c.addStatement("g1", "s2", "asset2")

	c.addPolicy("r1", "p1", []string{"s1"})
	c.addPolicy("r1", "p2", []string{"s1", "s2"})
	c.addPolicy("g1", "p1", []string{"s1"})
	c.addPolicy("g1", "p2", []string{"s1", "s2"})

	err = c.addPolicyAssignment("r1", []string{"p1", "p2"})
	assert.Nil(t, err)
	err = c.addPolicyAssignment("g1", []string{"p1", "p2"})
	assert.Nil(t, err)

	err = c.addPath("g1", "10.0.10.0/24")
	assert.Nil(t, err)
	err = c.connectPeers("r1", "g1", false, false)
	assert.Nil(t, err)
}
