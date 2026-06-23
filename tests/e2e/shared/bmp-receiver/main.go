package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	bgpPkg "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

func main() {
	ln, err := net.Listen("tcp", ":11019")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	log.Printf("bmp-receiver listening on :11019")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	log.Printf("connection from %s", conn.RemoteAddr())
	for {
		raw, err := readBMPMessage(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("read: %v", err)
			}
			return
		}
		msg, err := bmp.ParseBMPMessage(raw)
		if err != nil {
			log.Printf("parse: %v", err)
			continue
		}
		handleMsg(msg)
	}
}

func readBMPMessage(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, bmp.BMP_HEADER_SIZE)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(hdr[1:5])
	if msgLen < uint32(bmp.BMP_HEADER_SIZE) {
		return nil, fmt.Errorf("invalid BMP message length: %d", msgLen)
	}
	rest := make([]byte, msgLen-uint32(bmp.BMP_HEADER_SIZE))
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	return append(hdr, rest...), nil
}

func emit(m map[string]interface{}) {
	data, err := json.Marshal(m)
	if err != nil {
		log.Printf("marshal: %v", err)
		return
	}
	fmt.Println(string(data))
}

func handleMsg(msg *bmp.BMPMessage) {
	switch body := msg.Body.(type) {
	case *bmp.BMPInitiation:
		m := map[string]interface{}{"type": "Initiation"}
		for _, tlv := range body.Info {
			if s, ok := tlv.(*bmp.BMPInfoTLVString); ok {
				switch s.Type {
				case bmp.BMP_INIT_TLV_TYPE_SYS_NAME:
					m["sysname"] = s.Value
				case bmp.BMP_INIT_TLV_TYPE_SYS_DESCR:
					m["sysdescr"] = s.Value
				}
			}
		}
		emit(m)

	case *bmp.BMPPeerUpNotification:
		ph := &msg.PeerHeader
		emit(map[string]interface{}{
			"type":        "PeerUp",
			"peer_type":   ph.PeerType,
			"peer_addr":   ph.PeerAddress.String(),
			"peer_asn":    ph.PeerAS,
			"bgp_id":      ph.PeerBGPID.String(),
			"post_policy": ph.IsPostPolicy(),
			"adj_rib_out": ph.IsAdjRIBOut(),
			"local_addr":  body.LocalAddress.String(),
		})

	case *bmp.BMPPeerDownNotification:
		ph := &msg.PeerHeader
		emit(map[string]interface{}{
			"type":      "PeerDown",
			"peer_type": ph.PeerType,
			"peer_addr": ph.PeerAddress.String(),
			"peer_asn":  ph.PeerAS,
			"reason":    body.Reason,
		})

	case *bmp.BMPRouteMonitoring:
		ph := &msg.PeerHeader
		update, ok := body.BGPUpdate.Body.(*bgpPkg.BGPUpdate)
		if !ok {
			return
		}
		postPolicy := ph.IsPostPolicy()
		adjRIBOut := ph.IsAdjRIBOut()
		peerType := ph.PeerType

		// Detect EoR: empty update with no path attributes (IPv4 EoR)
		if len(update.NLRI) == 0 && len(update.WithdrawnRoutes) == 0 {
			// Check for MP_UNREACH_NLRI EoR (non-IPv4) or plain IPv4 EoR
			afi, safi := uint16(bgpPkg.AFI_IP), uint8(bgpPkg.SAFI_UNICAST)
			isEoR := true
			for _, pa := range update.PathAttributes {
				if pa.GetType() == bgpPkg.BGP_ATTR_TYPE_MP_UNREACH_NLRI {
					mp := pa.(*bgpPkg.PathAttributeMpUnreachNLRI)
					if len(mp.Value) == 0 {
						afi = mp.AFI
						safi = mp.SAFI
					} else {
						isEoR = false
					}
				} else {
					isEoR = false
					break
				}
			}
			if isEoR {
				emit(map[string]interface{}{
					"type":        "RouteMonitoring",
					"peer_type":   peerType,
					"peer_addr":   ph.PeerAddress.String(),
					"peer_asn":    ph.PeerAS,
					"post_policy": postPolicy,
					"adj_rib_out": adjRIBOut,
					"eor":         true,
					"afi":         afi,
					"safi":        safi,
				})
				return
			}
		}

		// Extract nexthop from path attributes
		nexthop := ""
		for _, pa := range update.PathAttributes {
			switch pa.GetType() {
			case bgpPkg.BGP_ATTR_TYPE_NEXT_HOP:
				nexthop = pa.(*bgpPkg.PathAttributeNextHop).Value.String()
			case bgpPkg.BGP_ATTR_TYPE_MP_REACH_NLRI:
				mp := pa.(*bgpPkg.PathAttributeMpReachNLRI)
				if len(mp.Nexthop) > 0 {
					nexthop = mp.Nexthop.String()
				}
				for _, nlri := range mp.Value {
					emit(map[string]interface{}{
						"type":        "RouteMonitoring",
						"peer_type":   peerType,
						"peer_addr":   ph.PeerAddress.String(),
						"peer_asn":    ph.PeerAS,
						"post_policy": postPolicy,
						"adj_rib_out": adjRIBOut,
						"prefix":      nlri.String(),
						"nexthop":     nexthop,
						"withdraw":    false,
					})
				}
			case bgpPkg.BGP_ATTR_TYPE_MP_UNREACH_NLRI:
				mp := pa.(*bgpPkg.PathAttributeMpUnreachNLRI)
				for _, nlri := range mp.Value {
					emit(map[string]interface{}{
						"type":        "RouteMonitoring",
						"peer_type":   peerType,
						"peer_addr":   ph.PeerAddress.String(),
						"peer_asn":    ph.PeerAS,
						"post_policy": postPolicy,
						"adj_rib_out": adjRIBOut,
						"prefix":      nlri.String(),
						"withdraw":    true,
					})
				}
			}
		}

		// IPv4 unicast reach
		for _, nlri := range update.NLRI {
			emit(map[string]interface{}{
				"type":        "RouteMonitoring",
				"peer_type":   peerType,
				"peer_addr":   ph.PeerAddress.String(),
				"peer_asn":    ph.PeerAS,
				"post_policy": postPolicy,
				"adj_rib_out": adjRIBOut,
				"prefix":      nlri.String(),
				"nexthop":     nexthop,
				"withdraw":    false,
			})
		}

		// IPv4 unicast withdraw
		for _, nlri := range update.WithdrawnRoutes {
			emit(map[string]interface{}{
				"type":        "RouteMonitoring",
				"peer_type":   peerType,
				"peer_addr":   ph.PeerAddress.String(),
				"peer_asn":    ph.PeerAS,
				"post_policy": postPolicy,
				"adj_rib_out": adjRIBOut,
				"prefix":      nlri.String(),
				"withdraw":    true,
			})
		}

	case *bmp.BMPTermination:
		emit(map[string]interface{}{"type": "Termination"})
	}
}
