package bgptest

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func disableEbgpPeer(t *testing.T, c *bgpTest) {
	err := c.disablePeer("g3", "r1")
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
	checkAdjout(t, c)
	has, _ := c.waitForPath("r1", global, "", "10.0.2.0/24", 50)
	assert.False(t, has)
}

func addEbgpPeer(t *testing.T, c *bgpTest) {
	err := c.createPeer("g3", gobgpImageName(), 2)
	assert.Nil(t, err)
	err = c.connectPeers("r1", "g3", false)
	assert.Nil(t, err)
	err = c.addPath("g3", "10.0.2.0/24")
	assert.Nil(t, err)
	c.waitForEstablish("g3")

	// g3 should receive routes from ibgp peers
	r, err := c.getTableCounter("g3", "r1")
	assert.Nil(t, err)
	assert.Equal(t, r.accepted, uint64(2))

	// r1 should update path attributes properly
	l, err := c.listPath("g3", adjin, "r1")
	assert.Nil(t, err)
	for _, p := range l {
		assert.Equal(t, p.nexthop, c.neighborAddress("r1"))
		assert.Equal(t, p.aspath[0], uint32(1))
	}

	l, err = c.listPath("g1", adjin, "r1")
	assert.Nil(t, err)
	for _, p := range l {
		// bgp router mustn't change nexthop of routes from eBGP peers
		// which are sent to iBGP peers
		assert.Equal(t, p.nexthop, c.neighborAddress("g3"))
		// bgp router mustn't change aspath of routes from eBGP peers
		// which are sent to iBGP peers
		assert.Equal(t, p.aspath[0], uint32(2))
	}
}

func checkAdjout(t *testing.T, c *bgpTest) {
	// should not send routes from ibgp to ibgp peers
	r, err := c.getTableCounter("g1", "r1")
	assert.Nil(t, err)
	assert.Equal(t, r.received, uint64(0))
	r, err = c.getTableCounter("g2", "r1")
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
	// test rustybgp passive connect
	err = c.connectPeers("r1", "g2", true)
	assert.Nil(t, err)
	err = c.connectPeers("g1", "g2", false)
	assert.Nil(t, err)

	waitForEstablish(t, c)
	checkGlobalrib(t, c)
	checkAdjout(t, c)
	addEbgpPeer(t, c)
	disableEbgpPeer(t, c)
	//	c.Stop()
}
