package bgptest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func checkGlobalRibNum(t *testing.T, c *bgpTest, name string, num int) {
	l, err := c.listPath(name, global, "")
	assert.Nil(t, err)
	assert.Equal(t, num, len(l))
}

func checkAdminDown(t *testing.T, c *bgpTest) {
	err := c.createPeer("g3", gobgpImageName(), 65004)
	assert.Nil(t, err)
	err = c.connectPeers("r1", "g3", false, true)
	assert.Nil(t, err)
	err = c.waitForEstablished("r1", "g3", 100)
	assert.NotNil(t, err)
	err = c.enablePeer("r1", "g3")
	assert.Nil(t, err)
	err = c.waitForEstablished("r1", "g3", 100)
	assert.Nil(t, err)
}

func TestAdmin(t *testing.T) {
	rustyImage := rustyImageName()
	fmt.Println("rusty image name ", rustyImage)
	gobgpImage := gobgpImageName()
	fmt.Println("gobgp image name ", gobgpImage)

	c, err := newBgpTest()
	assert.Nil(t, err)
	err = c.createPeer("r1", rustyImage, 65000)
	assert.Nil(t, err)

	peers := []string{"g1", "g2"}
	for i, p := range peers {
		err = c.createPeer(p, gobgpImage, 65001+uint32(i))
		assert.Nil(t, err)
		err = c.connectPeers("r1", p, true, false)
		assert.Nil(t, err)
		err := c.addPath(p, fmt.Sprintf("10.0.%d.0/24", i+1))
		assert.Nil(t, err)
	}

	c.waitForAllEstablish("r1")
	checkGlobalRibNum(t, c, "r1", 2)

	c.deletePeer("r1", "g1")

	c.waitForActive("g1", "r1")

	checkGlobalRibNum(t, c, "g2", 1)
	// rustybgp sent notification?
	m, err := c.getMessageCounter("g1", "r1")
	assert.Nil(t, err)
	assert.Equal(t, uint64(1), m.notification)

	checkAdminDown(t, c)
}
