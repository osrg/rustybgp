package bgptest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func checkAdjout(t *testing.T, c *bgpTest) {
	// should not send routes from ibgp to ibgp peers
	r, err := c.getCounter("g1", "r1")
	assert.Nil(t, err)
	assert.Equal(t, r.received, uint64(0))
	r, err = c.getCounter("g2", "r1")
	assert.Nil(t, err)
	assert.Equal(t, r.received, uint64(0))

	has, _ := c.waitForPath("r1", adjout, "g2", "10.0.0.0/24", 50)
	assert.False(t, has)
	has, _ = c.waitForPath("r1", adjout, "g1", "10.0.1.0/24", 50)
	assert.False(t, has)
}

func checkGlobalrib(t *testing.T, c *bgpTest) {
	err := c.addPath("g1", "10.0.0.0/24")
	assert.Nil(t, err)
	err = c.addPath("g2", "10.0.1.0/24")
	assert.Nil(t, err)
	has, _ := c.waitForPath("r1", global, "", "10.0.0.0/24", 50)
	assert.True(t, has)
	has, _ = c.waitForPath("r1", global, "", "10.0.1.0/24", 50)
	assert.True(t, has)
}

func waitForEstablish(t *testing.T, c *bgpTest) {
	c.waitForEstablish("g1")
	c.waitForEstablish("g2")
}

func TestIbgp(t *testing.T) {
	rustyImage := rustyImageName()
	fmt.Println("rusty image name ", rustyImage)
	gobgpImage := gobgpImageName()
	fmt.Println("gobgp image name ", gobgpImage)

	c, err := newBgpTest()
	assert.Nil(t, err)
	err = c.createPeer("r1", rustyImage, 1)
	assert.Nil(t, err)
	err = c.createPeer("g1", gobgpImage, 1)
	assert.Nil(t, err)
	err = c.createPeer("g2", gobgpImage, 1)
	assert.Nil(t, err)

	// test rustybgp active connect
	err = c.connectPeers("g1", "r1", true)
	assert.Nil(t, err)
	err = c.connectPeers("g2", "r1", false)
	assert.Nil(t, err)
	err = c.connectPeers("g1", "g2", false)
	assert.Nil(t, err)

	waitForEstablish(t, c)
	checkGlobalrib(t, c)
	checkAdjout(t, c)
	//	c.Stop()
}
