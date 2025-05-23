// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"fmt"

	"github.com/agntcy/dir/utils/logging"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

var logger = logging.Logger("p2p")

type Server struct {
	opts    *options
	host    host.Host
	dht     *dht.IpfsDHT
	closeFn func()
}

// New constructs a new p2p server.
func New(ctx context.Context, opts ...Option) (*Server, error) {
	logger.Debug("Creating new p2p server", "opts", opts)

	// Load options
	options := &options{}
	for _, opt := range append(opts, withRandomIdentity()) {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	// Start in the background.
	// Wait for ready status message before returning.
	status := <-start(ctx, options)
	if status.Err != nil {
		return nil, fmt.Errorf("failed while starting services: %w", status.Err)
	}

	server := &Server{
		opts:    options,
		host:    status.Host,
		dht:     status.DHT,
		closeFn: status.Close,
	}

	logger.Debug("P2P server created", "host", server.host.ID(), "addresses", server.P2pAddrs())

	return server, nil
}

// Info returns the addresses at which we can reach this server.
func (s *Server) Info() *peer.AddrInfo {
	return &peer.AddrInfo{
		ID:    s.host.ID(),
		Addrs: s.host.Addrs(),
	}
}

// Returns p2p specific addresses as addrinfos.
func (s *Server) P2pInfo() []peer.AddrInfo {
	var p2pInfos []peer.AddrInfo //nolint:prealloc

	for _, addr := range s.P2pAddrs() {
		p2pInfo, _ := peer.AddrInfoFromString(addr)
		p2pInfos = append(p2pInfos, *p2pInfo)
	}

	return p2pInfos
}

// Returns p2p specific addresses as strings.
func (s *Server) P2pAddrs() []string {
	var p2pAddrs []string //nolint:prealloc
	for _, addr := range s.host.Addrs() {
		p2pAddrs = append(p2pAddrs, fmt.Sprintf("%s/p2p/%s", addr.String(), s.host.ID().String()))
	}

	return p2pAddrs
}

func (s *Server) Host() host.Host {
	return s.host
}

func (s *Server) DHT() *dht.IpfsDHT {
	return s.dht
}

func (s *Server) Key() crypto.PrivKey {
	return s.host.Peerstore().PrivKey(s.host.ID())
}

// Close stops running services.
func (s *Server) Close() {
	s.closeFn()
}

type status struct {
	Err   error
	Host  host.Host
	DHT   *dht.IpfsDHT
	Close func()
}

// start starts all routing related services.
// This function runs until ctx is closed.
//
// TODO: maybe limit how long we should wait for status channel
// via contexts.
func start(ctx context.Context, opts *options) <-chan status {
	statusCh := make(chan status)

	go func() {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Create host
		host, err := newHost(opts.ListenAddress, opts.Key)
		if err != nil {
			statusCh <- status{Err: err}

			return
		}

		defer host.Close()
		logger.Debug("Host created", "id", host.ID(), "addresses", host.Addrs())

		// Create DHT
		var customDhtOpts []dht.Option
		if opts.DHTCustomOpts != nil {
			customDhtOpts, err = opts.DHTCustomOpts(host)
			if err != nil {
				statusCh <- status{Err: err}

				return
			}
		}

		kdht, err := newDHT(ctx, host, opts.BootstrapPeers, opts.RefreshInterval, customDhtOpts...)
		if err != nil {
			statusCh <- status{Err: err}

			return
		}
		defer kdht.Close()

		// Start peer discovery if requested
		if opts.Randevous != "" {
			go discover(ctx, host, kdht, opts.Randevous)
		}

		// Register services. Only available on non-bootstrap nodes.
		if opts.APIRegistrer != nil && len(opts.BootstrapPeers) > 0 {
			err := opts.APIRegistrer(host)
			if err != nil {
				statusCh <- status{Err: err}

				return
			}
		}

		// Run until context expiry
		logger.Debug("Host and DHT created, running routing services", "host", host.ID(), "addresses", host.Addrs())

		for _, peer := range opts.BootstrapPeers {
			for _, addr := range peer.Addrs {
				host.Peerstore().AddAddr(peer.ID, addr, 0)
			}
		}

		<-kdht.RefreshRoutingTable()

		// At this point, we are done.
		// Notify listener that we are ready.
		statusCh <- status{
			Host: host,
			DHT:  kdht,
			Close: func() {
				cancel()
				host.Close()
				kdht.Close()
			},
		}

		// Wait for context to close
		<-ctx.Done()
	}()

	return statusCh
}
