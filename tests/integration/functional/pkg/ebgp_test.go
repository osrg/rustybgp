package bgptest

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func checkPathAttr(t *testing.T, c *bgpTest, peers []string) {
	for _, peer := range peers {
		// check if routes are properly advertised
		var l []path
		for i := 0; i < 100; i++ {
			var err error
			l, err = c.listPath(peer, adjin, "r1")
			assert.Nil(t, err)
			if len(l) < 2 {
				time.Sleep(time.Millisecond * 100)
			} else {
				break
			}
		}
		assert.Equal(t, len(l), 2)
		for _, p := range l {
			// check if the nexthop is updated
			assert.Equal(t, p.nexthop, c.neighborAddress("r1"))
			// check if the own asn is added to aspath
			assert.Equal(t, p.aspath[0], uint32(65000))
			assert.Equal(t, len(p.aspath), 2)
		}
	}

	// check if adjin works
	l, err := c.listPath("r1", adjin, "g1")
	assert.Nil(t, err)
	assert.Equal(t, len(l), 1)
	assert.Equal(t, l[0].nlri, "10.0.1.0/24")
}

func checkGlobalRib(t *testing.T, c *bgpTest) {
	l, err := c.listPath("r1", global, "")
	assert.Nil(t, err)
	assert.Equal(t, len(l), 3)
}

func TestEbgp(t *testing.T) {
	rustyImage := rustyImageName()
	fmt.Println("rusty image name ", rustyImage)
	gobgpImage := gobgpImageName()
	fmt.Println("gobgp image name ", gobgpImage)

	c, err := newBgpTest()
	assert.Nil(t, err)
	err = c.createPeer("r1", rustyImage, 65000)
	assert.Nil(t, err)

	peers := []string{"g1", "g2", "g3"}
	// test rustybgp active connect
	for i, p := range peers {
		err = c.createPeer(p, gobgpImage, 65001+uint32(i))
		assert.Nil(t, err)
		err = c.connectPeers(p, "r1", true)
		assert.Nil(t, err)
		err := c.addPath(p, fmt.Sprintf("10.0.%d.0/24", i+1))
		assert.Nil(t, err)
	}

	c.waitForEstablish("r1")
	checkGlobalRib(t, c)
	checkPathAttr(t, c, peers)
	//	c.Stop()
}
