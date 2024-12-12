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
	"fmt"
	"log"
	"net"
)

func (server *Server) runListener(listener net.Listener, ctx context.Context) {
	// Handle new TCP connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		client := &TlsConnection{
			conn: conn,
		}
		server.wg.Add(1)
		go func() {
			err := client.handleRequest(ctx)
			if err != nil {
				log.Printf("request error: %v", err)
			}
		}()
	}
}

func (server *Server) Run(address ListenConfig, ctx context.Context) error {
	listener, err := net.Listen("tcp", string(address))
	if err != nil {
		return fmt.Errorf("listen error: %v", err)
	}

	// Shutdown the listener when the context ends.
	server.wg.Add(1)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Run the listener loop.
	server.wg.Add(1)
	go server.runListener(listener, ctx)
	return nil
}
