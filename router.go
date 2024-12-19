// Copyright (C) 2024  Naomi Kirby
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"sync"
	"time"
)

type RouteRegex struct {
	relist []*regexp.Regexp
}

func (list *RouteRegex) MatchString(s string) bool {
	for _, re := range list.relist {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (list *RouteRegex) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw interface{}
	err := unmarshal(&raw)
	if err != nil {
		return err
	}

	// We can accept a single string
	if pattern, ok := raw.(string); ok {
		r, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex: %s", pattern)
		}
		list.relist = make([]*regexp.Regexp, 1)
		list.relist[0] = r
		return nil
	}

	// Or, we can accept a list of strings.
	if rlist, ok := raw.([]string); ok {
		list.relist = make([]*regexp.Regexp, len(rlist))
		for index, pattern := range rlist {
			r, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex: %s", pattern)
			}
			list.relist[index] = r
		}
		return nil
	}

	// Otherwise, we don't support this type.
	return fmt.Errorf("invalid type")
}

func (list RouteRegex) IsZero() bool {
	return len(list.relist) == 0
}

func (list RouteRegex) MarshalYAML() (interface{}, error) {
	if len(list.relist) == 0 {
		return nil, nil
	} else if len(list.relist) == 1 {
		return list.relist[0].String(), nil
	} else {
		result := make([]string, len(list.relist))
		for index, re := range list.relist {
			result[index] = re.String()
		}
		return result, nil
	}
}

type RouteTarget struct {
	Host   string
	Weight uint

	tcpAddr *net.TCPAddr
}

type routeTargetRaw struct {
	Host   string `yaml:"host"`
	Weight uint   `yaml:"weight"`
}

func (target *RouteTarget) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw interface{}
	err := unmarshal(&raw)
	if err != nil {
		log.Printf("unmarshal error: %v", err)
	}
	if addrString, ok := raw.(string); ok {
		// The target can be a string, in which case we should give it default values.
		target.Host = addrString
		target.Weight = 100
	} else {
		// Otherwise, try to unmarshal it as a struct.
		rtStruct := routeTargetRaw{}
		err := unmarshal(&rtStruct)
		if err != nil {
			return err
		}
		target.Host = rtStruct.Host
		target.Weight = rtStruct.Weight
	}

	return nil
}

type RouteConfig struct {
	AlpnProtocols RouteRegex    `yaml:"alpn,omitempty"`
	SniNames      RouteRegex    `yaml:"sni,omitempty"`
	Ciphers       RouteRegex    `yaml:"ciphers,omitempty"`
	Targets       []RouteTarget `yaml:"targets"`
}

func (route *RouteConfig) MatchesConnection(client *TlsConnection) bool {
	for _, name := range client.ServerNames {
		if route.SniNames.MatchString(name) {
			return true
		}
	}

	for _, proto := range client.AlpnProtocols {
		if route.AlpnProtocols.MatchString(proto) {
			return true
		}
	}

	for _, suite := range client.ClientHello.CipherSuites {
		if route.Ciphers.MatchString(suite.String()) {
			return true
		}
	}

	// Otherwise - no match.
	return false
}

// Iterate through the list of routes and the hostnames.
// TODO: This could be done periodically, or maybe even integrate heartbeats.
func (server *Server) ResolveRoutes() {
	for ridx, route := range server.conf.Routes {
		for tidx, target := range route.Targets {
			addr, err := net.ResolveTCPAddr("tcp", target.Host)
			if err != nil {
				log.Printf("resolution failed for %s", target.Host)
				server.conf.Routes[ridx].Targets[tidx].tcpAddr = nil
				continue
			}
			log.Printf("Resolved %s -> %s", target.Host, addr.String())
			server.conf.Routes[ridx].Targets[tidx].tcpAddr = addr
		}
	}
}

func (server *Server) runConnection(conn *net.TCPConn, ctx context.Context) {
	tcon := &TlsConnection{
		client: conn,
		config: &server.conf,
	}
	defer tcon.Close()

	// Create a context for the connection handshake. If we don't get a complete
	// ClientHello within its timeout, then we should give up and close the
	// connection.
	hsCtx, hsCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer hsCancel()
	go func() {
		<-hsCtx.Done()
		if !errors.Is(hsCtx.Err(), context.Canceled) {
			log.Printf("handshake error: %v", hsCtx.Err())
			tcon.client.Close()
		}
	}()

	// Process the handshake and get the ClientHello
	err := tcon.handleRequest(ctx)
	if err != nil {
		log.Printf("request error: %v", err)
		return
	}
	hsCancel()

	// Check if the client matches a route.
	for _, route := range server.conf.Routes {
		if !route.MatchesConnection(tcon) {
			continue
		}

		// Dial a connection to the backend.
		// TODO: This needs a timeout
		backend, err := net.DialTCP("tcp", nil, route.Targets[0].tcpAddr)
		if err != nil {
			return
		}
		tcon.backend = backend
		err = sendClientHello(tcon.backend, tcon.helloData)
		if err != nil {
			return
		}

		// Exchange data between client and backend.
		wg := sync.WaitGroup{}
		defer wg.Wait()
		wg.Add(1)
		go func() {
			err := tcon.handleOutbound()
			if err != nil {
				log.Printf("backend error: %v", err)
			}
			wg.Done()
		}()

		err = tcon.handleInbound()
		if err != nil {
			log.Printf("pipe error: %v", err)
		}
		return
	}

	// If we get this far, there is nowhere to route the connection to.
	// TODO: We should probably respond with a TLS alert.
}

func (server *Server) runListener(listener *net.TCPListener, ctx context.Context) {
	// Handle new TCP connections.
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}

		server.wg.Add(1)
		go func() {
			server.runConnection(conn, ctx)
			server.wg.Done()
		}()
	}
}

func (server *Server) Run(address ListenConfig, ctx context.Context) error {
	// Resolve the routes to the backend targets.
	server.ResolveRoutes()

	// Open the listening port.
	localAddr, err := net.ResolveTCPAddr("tcp", string(address))
	if err != nil {
		return fmt.Errorf("listen address error: %v", err)
	}
	listener, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("listen error: %v", err)
	}

	// Shutdown the listener when the context ends.
	server.wg.Add(1)
	go func() {
		<-ctx.Done()
		listener.Close()
		server.wg.Done()
	}()

	// Run the listener loop.
	server.wg.Add(1)
	go func() {
		server.runListener(listener, ctx)
		server.wg.Done()
	}()

	return nil
}
