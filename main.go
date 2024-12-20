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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gopkg.in/yaml.v3"
)

type ListenConfig string

type Configuration struct {
	Listen     []ListenConfig         `yaml:"listen"`
	ECHConfigs ECHConfigList          `yaml:"ech"`
	Routes     map[string]RouteConfig `yaml:"routes"`

	// verbose logging can only be enabled from the command line.
	verbose    bool
}

type Server struct {
	conf Configuration
	wg   sync.WaitGroup
}

// Custom error type to indicate we are exiting on a signal.
type SignalError struct {
	sig os.Signal
}

func (s SignalError) Error() string {
	return s.sig.String()
}
func (s SignalError) Signal() syscall.Signal {
	signo, okay := s.sig.(syscall.Signal)
	if okay {
		return signo
	} else {
		return 0
	}
}

func (c *Configuration) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return err
	}
	return nil
}

func (conf *Configuration) run() error {
	server := Server{
		conf: *conf,
	}
	defer server.wg.Wait()

	// Start the listeners
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, listener := range server.conf.Listen {
		err := server.Run(listener, ctx)
		if err != nil {
			return err
		}
	}

	// Run until terminated
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(done)

	switch sig := <-done; sig {
	case syscall.SIGINT:
		fallthrough
	case syscall.SIGTERM:
		return nil
	default:
		return SignalError{sig: sig}
	}
}

func main() {
	var (
		conf Configuration
		configFile string
		genHpkeKey string
		genEchSvcb bool
	)

	// Parse the configuration and command line options.
	flag.StringVar(&configFile, "c", "", "Configuration file")
	flag.StringVar(&genHpkeKey, "g", "", "Generate HPKE private key")
	flag.BoolVar(&genEchSvcb, "s", false, "Generate ECH SVCB record")
	flag.BoolVar(&conf.verbose, "v", false, "Verbose logging")
	flag.Parse()

	// If we requested HPKE key generation, generate the key and exit.
	if len(genHpkeKey) != 0 {
		err := RunHpkeGenerateKey(genHpkeKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hpke key generation failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Parse the configuration file.
	if len(configFile) > 0 {
		err := conf.LoadFromFile(configFile)
		if err != nil {
			log.Printf("error: %v", err)
			os.Exit(1)
		}
	}

	// Setup the ECH configuration
	for index, _ := range conf.ECHConfigs {
		err := conf.ECHConfigs[index].SetupPrivate()
		if err != nil {
			log.Printf("hpke key setup failed: %v", err)
			os.Exit(1)
		}
	}

	// If we requested ECH SVCB record generate, generate the record and exit.
	if genEchSvcb {
		err := RunEchGenerateSvcb(conf.ECHConfigs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcb generation failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Run the service
	err := conf.run()
	if s, ok := err.(SignalError); ok {
		log.Printf("caught signal: %v", err)
		os.Exit(128 + int(s.Signal()))
	} else {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}
