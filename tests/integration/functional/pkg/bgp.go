package bgptest

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/grpc"

	api "github.com/osrg/gobgp/api"
)

func rustyImageName() string {
	const imageNameEnv = "RUSTYBGP_IMAGE_NAME"

	if n := os.Getenv(imageNameEnv); n != "" {
		return n
	}
	return "rustybgp-ci"
}

func gobgpImageName() string {
	const imageNameEnv = "GOBGY_IMAGE_NAME"

	if n := os.Getenv(imageNameEnv); n != "" {
		return n
	}
	return "docker.pkg.github.com/fujita/gobgp/gobgp-daemon"
}

type peer struct {
	id        string
	ip        net.IP
	as        uint32
	apiClient api.GobgpApiClient
}

type bgpTest struct {
	client     *client.Client
	containers map[string]*peer
}

func newBgpTest() (t *bgpTest, err error) {
	cli, err := client.NewClientWithOpts(client.WithVersion("1.40"))
	if err != nil {
		return nil, err
	}
	return &bgpTest{
		client:     cli,
		containers: make(map[string]*peer),
	}, nil
}

func (b *bgpTest) stop() {
	cr := types.ContainerRemoveOptions{
		Force: true,
	}
	for _, peer := range b.containers {
		if err := b.client.ContainerRemove(context.Background(), peer.id, cr); err != nil {
			fmt.Println(err)
		}
	}
}

const grpcPort = "50051/tcp"

func (b *bgpTest) createPeer(name, image string, as uint32) error {
	cc := &container.Config{
		Image: image,
		ExposedPorts: nat.PortSet{
			grpcPort: {},
		},
		Labels: map[string]string{"rustybgp-ci": ""},
	}
	hc := &container.HostConfig{
		PublishAllPorts: true,
	}
	nc := &network.NetworkingConfig{}
	r, err := b.client.ContainerCreate(context.Background(), cc, hc, nc, name)
	if err != nil {
		fmt.Println("can't create container ", err)
		return err
	}

	err = b.client.ContainerStart(context.Background(), r.ID, types.ContainerStartOptions{})
	if err != nil {
		fmt.Println("can't start container ", err)
		return err
	}
	j, err := b.client.ContainerInspect(context.Background(), r.ID)
	if err != nil {
		fmt.Println("can't inspect container ", err)
		return err
	}
	localIP := net.ParseIP(j.NetworkSettings.DefaultNetworkSettings.IPAddress)
	port := uint64(0)
	for _, h := range j.NetworkSettings.NetworkSettingsBase.Ports[grpcPort] {
		port, _ = strconv.ParseUint(h.HostPort, 10, 16)
	}

	grpcOpts := []grpc.DialOption{grpc.WithBlock(), grpc.WithInsecure()}
	conn, err := grpc.DialContext(context.Background(), fmt.Sprintf("127.0.0.1:%d", port), grpcOpts...)
	if err != nil {
		fmt.Println("can't connect ", err)
		return err
	}
	client := api.NewGobgpApiClient(conn)
	_, err = client.StartBgp(context.Background(),
		&api.StartBgpRequest{
			Global: &api.Global{
				As:       as,
				RouterId: localIP.String(),
			},
		})
	if err != nil {
		fmt.Println("can't start ", err)
		return err
	}
	b.containers[name] = &peer{
		id:        r.ID,
		as:        as,
		ip:        localIP,
		apiClient: client,
	}
	return nil
}

func (b *bgpTest) addPeer(name1, name2 string, passive bool) error {
	p1 := b.containers[name1]
	p2 := b.containers[name2]
	_, err := p1.apiClient.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: p2.ip.String(),
				PeerAs:          p2.as,
			},
			Transport: &api.Transport{
				PassiveMode: passive,
			},
			Timers: &api.Timers{
				Config: &api.TimersConfig{
					ConnectRetry:           1,
					IdleHoldTimeAfterReset: 1,
				},
			},
		},
	})
	return err
}

func (b *bgpTest) connectPeers(name1, name2 string, passive bool) error {
	if err := b.addPeer(name1, name2, passive); err != nil {
		fmt.Println(err)
		return err
	}
	if passive == true {
		passive = false
	}
	if err := b.addPeer(name2, name1, passive); err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func (b *bgpTest) waitForEstablish(name string) error {
	for {
		stream, err := b.containers[name].apiClient.ListPeer(context.Background(), &api.ListPeerRequest{})
		if err != nil {
			fmt.Println(err)
			return err
		}
		notEstablished := false
		for {
			r, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				fmt.Println(err)
				return err
			}
			if r.Peer.State.SessionState != api.PeerState_ESTABLISHED {
				notEstablished = true
				break
			}
		}
		if !notEstablished {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

func prefixToAPI(prefix string) (*api.IPAddressPrefix, *api.Family, error) {
	ip, net, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, nil, err
	}
	family := func() *api.Family {
		if ip.To4() == nil {
			return &api.Family{
				Afi:  api.Family_AFI_IP6,
				Safi: api.Family_SAFI_UNICAST,
			}
		}
		return &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
	}()
	l, _ := net.Mask.Size()
	return &api.IPAddressPrefix{
		Prefix:    ip.String(),
		PrefixLen: uint32(l),
	}, family, nil
}

func (b *bgpTest) addPath(name, prefix string) error {
	p, family, err := prefixToAPI(prefix)
	if err != nil {
		return err
	}
	nlri, _ := ptypes.MarshalAny(p)
	a1, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: 0,
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: b.containers[name].ip.String(),
	})
	attrs := []*any.Any{a1, a2}

	_, err = b.containers[name].apiClient.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri,
			Pattrs: attrs,
		},
	})
	return err
}

type tableType int

const (
	global tableType = 0
	//	TableType_LOCAL   TableType = 1
	adjin  tableType = 2
	adjout tableType = 3
)

func (b *bgpTest) waitForPath(name string, table tableType, neighbor, prefix string, retry int) (bool, error) {
	_, family, err := prefixToAPI(prefix)
	if err != nil {
		return false, err
	}
	var tableName string
	if neighbor != "" {
		tableName = neighbor
	}
	for i := 0; i < retry; i++ {
		stream, err := b.containers[name].apiClient.ListPath(context.Background(), &api.ListPathRequest{
			TableType: api.TableType(table),
			Family:    family,
			Name:      tableName,
		})
		if err != nil {
			return false, err
		}
		for {
			r, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return false, err
			}
			if r.Destination.Prefix == prefix {
				return true, nil
			}
		}
		time.Sleep(time.Millisecond * 100)
	}
	return false, nil
}

type messageCounter struct {
	advertised uint64
	received   uint64
	accepted   uint64
}

func (b *bgpTest) getCounter(name, neighbor string) (messageCounter, error) {
	c := messageCounter{}
	stream, err := b.containers[name].apiClient.ListPeer(context.Background(), &api.ListPeerRequest{Address: b.containers[neighbor].ip.String(), EnableAdvertised: true})
	if err != nil {
		return c, err
	}

	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return c, err
		}
		for _, a := range r.Peer.AfiSafis {
			if a.State.Family.Afi == api.Family_AFI_IP {
				return messageCounter{
					advertised: a.State.Advertised,
					received:   a.State.Received,
					accepted:   a.State.Accepted,
				}, nil
			}
		}

	}
	return c, fmt.Errorf("not found")
}
