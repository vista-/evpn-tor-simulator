package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgplog "github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "bgp-evpn-sim",
		Short: "Lightweight BGP EVPN route injector (simulator)",
		RunE:  run,
	}

	flagLocalAddresses []string
	flagNeighbors      []string
	flagRRs            []string
	flagNeighborAS     []uint
	flagRRAS           uint
	flagLoopbackBase   string
	flagToR            uint
	flagBD             uint
	flagMACperBD       uint

	logger *log.Logger
)

const (
	torASNBase = 82000
)

func init() {
	rootCmd.PersistentFlags().StringSliceVar(&flagLocalAddresses, "localaddrs", []string{"10.11.0.1"}, "comma-separated list of local interface addresses")
	rootCmd.PersistentFlags().StringSliceVar(&flagNeighbors, "neighbors", []string{"10.11.0.0"}, "comma-separated list of eBGP neighbors ip:port")
	rootCmd.PersistentFlags().StringSliceVar(&flagRRs, "rrs", []string{"1.1.1.1", "2.2.2.2"}, "comma-separate list of route reflectors ip:port")
	rootCmd.PersistentFlags().UintSliceVar(&flagNeighborAS, "neighbor-as", []uint{65011}, "comma-separated list of eBGP neighbor ASNs")
	rootCmd.PersistentFlags().UintVar(&flagRRAS, "rr-as", 65500, "route reflector ASN")
	rootCmd.PersistentFlags().StringVar(&flagLoopbackBase, "loopback-base", "10.0.0.0", "base address for loopback address generation")
	rootCmd.PersistentFlags().UintVar(&flagToR, "id", 1, "ToR ID")
	rootCmd.PersistentFlags().UintVar(&flagBD, "bridge-domains", 1, "number of bridge domains on ToR")
	rootCmd.PersistentFlags().UintVar(&flagMACperBD, "macs-per-bd", 48, "number of MACs to send per BD")
}

func generateType2Routes(hostID, countBD, countMAC uint, nexthopAddr netip.Addr) ([]*apiutil.Path, error) {
	routeCount := countBD * countMAC
	routes := make([]*apiutil.Path, routeCount)

	routeIdx := 0
	for bd := uint(1); bd <= countBD; bd++ {
		for idx := range routeCount / countBD {
			mac := fmt.Sprintf("02:00:00:%02x:%02x:%02x", hostID%256, bd, idx%256)
			// Optional: IP for MAC-IP routes...
			//ip, err := netip.ParseAddr(fmt.Sprintf("9.%d.%d.%d", hostID%256, (idx/256)%256, idx%256))
			//if err != nil {
			//	return nil, fmt.Errorf("could not parse IP: %v", err)
			//}

			rd, err := bgp.NewRouteDistinguisherIPAddressAS(nexthopAddr, uint16(bd))
			if err != nil {
				return nil, fmt.Errorf("could not create RD: %v", err)
			}

			nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(
				rd,
				bgp.EthernetSegmentIdentifier{
					Type:  bgp.ESI_ARBITRARY,
					Value: make([]byte, 9),
				},
				0,
				mac,
				netip.MustParseAddr("0.0.0.0"),
				[]uint32{uint32(bd)},
			)
			if err != nil {
				return nil, fmt.Errorf("could not create EVPN MAC-IP route: %v", err)
			}

			originAttr := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)
			nexthopAttr, err := bgp.NewPathAttributeNextHop(nexthopAddr)
			if err != nil {
				return nil, fmt.Errorf("could not create next-hop path attribute: %v", err)
			}

			route := &apiutil.Path{
				Nlri:   nlri,
				Family: bgp.RF_EVPN,
				Attrs:  []bgp.PathAttributeInterface{originAttr, nexthopAttr},
			}

			logger.Debugf("generated route: %v", route)

			routes[routeIdx] = route
			routeIdx++
		}
	}

	return routes, nil
}

func generateType5Routes(hostID, countBD, countMAC uint, nexthopAddr netip.Addr) ([]*apiutil.Path, error) {
	routeCount := countBD * countMAC
	routes := make([]*apiutil.Path, routeCount)

	routeIdx := 0
	for bd := uint(1); bd <= countBD; bd++ {
		for idx := range routeCount / countBD {
			ip, err := netip.ParseAddr(fmt.Sprintf("9.%d.%d.%d", hostID%256, bd, idx%256))
			if err != nil {
				return nil, fmt.Errorf("could not parse IP: %v", err)
			}

			rd, err := bgp.NewRouteDistinguisherIPAddressAS(nexthopAddr, uint16(bd))
			if err != nil {
				return nil, fmt.Errorf("could not create RD: %v", err)
			}

			nlri, err := bgp.NewEVPNIPPrefixRoute(
				rd,
				bgp.EthernetSegmentIdentifier{
					Type:  bgp.ESI_ARBITRARY,
					Value: make([]byte, 9),
				},
				0,
				32,
				ip,
				nexthopAddr,
				uint32(bd),
			)

			if err != nil {
				return nil, fmt.Errorf("could not create EVPN MAC-IP route: %v", err)
			}

			originAttr := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)
			nexthopAttr, err := bgp.NewPathAttributeNextHop(nexthopAddr)
			if err != nil {
				return nil, fmt.Errorf("could not create next-hop path attribute: %v", err)
			}

			route := &apiutil.Path{
				Nlri:   nlri,
				Family: bgp.RF_EVPN,
				Attrs:  []bgp.PathAttributeInterface{originAttr, nexthopAttr},
			}

			logger.Debugf("generated route: %v", route)

			routes[routeIdx] = route
			routeIdx++
		}
	}

	return routes, nil
}

func generateLoopbackRoutes(loopbackAddress netip.Addr) ([]*apiutil.Path, error) {
	loopbackRoutes := make([]*apiutil.Path, 1)

	loopbackInterface, err := loopbackAddress.Prefix(32)
	if err != nil {
		return nil, fmt.Errorf("could not create ip prefix out of loopback address: %v", err)
	}

	nlri, err := bgp.NewIPAddrPrefix(loopbackInterface)
	if err != nil {
		return nil, fmt.Errorf("could not create IP NLRI: %v", err)
	}
	originAttr := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)

	// Next-hop 0.0.0.0 means local route, it will get replaced by next-hop automatically in eBGP session
	nextHopAttr, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
	if err != nil {
		return nil, fmt.Errorf("could not create next-hop path attribute: %v", err)
	}

	route := &apiutil.Path{
		Nlri:   nlri,
		Family: bgp.RF_IPv4_UC,
		Attrs:  []bgp.PathAttributeInterface{originAttr, nextHopAttr},
	}

	logger.Debugf("generated route: %v", route)

	loopbackRoutes[0] = route

	return loopbackRoutes, nil
}

func addRoutes(server *server.BgpServer, routes []*apiutil.Path) error {
	logger.Debugf("Adding BGP routes: %v...", routes)
	addPathRequest := apiutil.AddPathRequest{
		Paths: routes,
	}

	_, err := server.AddPath(addPathRequest)
	if err != nil {
		return fmt.Errorf("could not send routes: %v", err)
	}

	return nil
}

func run(_ *cobra.Command, _ []string) error {
	log.SetLevel(log.InfoLevel)

	serveToR(flagToR, flagBD, flagMACperBD)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	<-sigs // block until Ctrl-C or kill
	return nil
}

func serveToR(hostID, countBD, countMAC uint) error {
	// 10.0.0.0/21 loopbacks
	loopbackAddress, _ := netip.ParseAddr(flagLoopbackBase)
	for range hostID {
		loopbackAddress = loopbackAddress.Next()
	}

	localAS := 82000 + hostID

	// prefix logs with ToR ID
	logger = log.WithPrefix(fmt.Sprintf("[ToR-%d]", hostID))

	logger.Infof("Starting ToR with loopback %v and localAS %v", loopbackAddress, localAS)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loggerBGP := log.WithPrefix(fmt.Sprintf("[ToR-%d-BGP]", hostID))
	loggerBGP.SetLevel(log.InfoLevel)
	bgpServer := server.NewBgpServer(server.LoggerOption(&myLogger{logger: loggerBGP}))
	go bgpServer.Serve()

	cfg := &api.StartBgpRequest{
		Global: &api.Global{
			Asn:      uint32(localAS),
			RouterId: loopbackAddress.String(),
		},
	}

	if err := bgpServer.StartBgp(ctx, cfg); err != nil {
		return fmt.Errorf("could not start BGP server: %v", err)
	}

	loopbackRoutes, err := generateLoopbackRoutes(loopbackAddress)
	if err != nil {
		return fmt.Errorf("could not generate loopback routes: %v", err)
	}

	if err := addRoutes(bgpServer, loopbackRoutes); err != nil {
		return fmt.Errorf("error adding loopback routes: %v", err)
	}

	var type2Routes []*apiutil.Path
	var type5Routes []*apiutil.Path

	if countBD > 1 {
		type2Routes, err = generateType2Routes(hostID, countBD, countMAC/2, loopbackAddress)
		if err != nil {
			return fmt.Errorf("error generating Type 2 routes: %v", err)
		}
		type5Routes, err = generateType5Routes(hostID, countBD, countMAC/2, loopbackAddress)
		if err != nil {
			return fmt.Errorf(" error generating Type 5 routes: %v", err)
		}
	} else {
		type5Routes, err = generateType5Routes(hostID, countBD, countMAC, loopbackAddress)
		if err != nil {
			return fmt.Errorf("error generating Type 5 routes: %v", err)
		}
	}

	if err := addRoutes(bgpServer, append(type2Routes, type5Routes...)); err != nil {
		return fmt.Errorf("error adding EVPN routes: %v", err)
	}

	emptyPolicy := &api.Policy{
		Name: "empty",
		Statements: []*api.Statement{
			{
				Name: "empty",
				Actions: &api.Actions{
					RouteAction: api.RouteAction_ROUTE_ACTION_REJECT,
				},
			},
		},
	}

	err = bgpServer.AddPolicy(ctx, &api.AddPolicyRequest{Policy: emptyPolicy})
	if err != nil {
		return fmt.Errorf("error adding policy: %v", err)
	}

	rejectPolicyAssignment := &api.PolicyAssignment{
		Name:          "global",
		Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
		DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		Policies:      []*api.Policy{emptyPolicy},
	}
	err = bgpServer.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{Assignment: rejectPolicyAssignment})
	if err != nil {
		return fmt.Errorf("error adding policy assignment: %v", err)
	}

	// Add the eBGP underlay spine neighbors
	for idx := range flagNeighbors {
		logger.Debugf("Configuring eBGP underlay neighbor %v (AS %v)...", flagNeighbors[idx], flagNeighborAS[idx])
		peer := &api.Peer{
			Conf: &api.PeerConf{
				PeerAsn:         uint32(flagNeighborAS[idx]),
				NeighborAddress: flagNeighbors[idx],
				LocalAsn:        uint32(localAS),
			},
			Transport: &api.Transport{
				PassiveMode: false,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
					},
				},
			},
		}

		if err := bgpServer.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
			return fmt.Errorf("could not add peer %v: %v", peer, err)
		}

		logger.Infof("Configured eBGP underlay neighbor %v (AS %v)", flagNeighbors[idx], flagNeighborAS[idx])
	}

	// Add iBGP RRs / neighbors
	for _, rr := range flagRRs {
		logger.Debugf("Configuring route reflector overlay neighbor %v (AS %v)...", rr, flagRRAS)
		peer := &api.Peer{
			Conf: &api.PeerConf{
				LocalAsn:        uint32(flagRRAS),
				PeerAsn:         uint32(flagRRAS),
				NeighborAddress: rr,
			},
			Transport: &api.Transport{
				LocalAddress: loopbackAddress.String(),
				PassiveMode:  false,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_L2VPN,
							Safi: api.Family_SAFI_EVPN,
						},
					},
				},
			},
		}

		if err := bgpServer.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
			return fmt.Errorf("could not add peer %v: %v", peer, err)
		}

		logger.Infof("Configured route reflector overlay neighbor %v (AS %v)", rr, flagRRAS)
	}

	logger.Infof("Advertised %d Type2 and %d Type5 routes", len(type2Routes), len(type5Routes))
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}

type myLogger struct {
	logger *log.Logger
}

func (l *myLogger) Panic(msg string, _ bgplog.Fields) {
	l.logger.Fatal(msg)
}

func (l *myLogger) Fatal(msg string, _ bgplog.Fields) {
	l.logger.Fatal(msg)
}

func (l *myLogger) Error(msg string, _ bgplog.Fields) {
	l.logger.Error(msg)
}

func (l *myLogger) Warn(msg string, _ bgplog.Fields) {
	l.logger.Warn(msg)
}

func (l *myLogger) Info(msg string, _ bgplog.Fields) {
	l.logger.Info(msg)
}

func (l *myLogger) Debug(msg string, _ bgplog.Fields) {
	l.logger.Debug(msg)
}

func (l *myLogger) SetLevel(level bgplog.LogLevel) {
	l.logger.SetLevel(log.Level(level))
}

func (l *myLogger) GetLevel() bgplog.LogLevel {
	return bgplog.LogLevel(log.GetLevel())
}
