package natscrypto

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/nats-io/gnatsd/server"
	"github.com/nats-io/nats"
)

const natsPort = 4242

// NatsTestServer wraps a gnatsd server.Server
type NatsTestServer struct {
	srv         *server.Server
	ready       bool
	ConnOptions nats.Options
}

// InitNatsTestServer returns a gnatsd test server
func InitNatsTestServer(t *testing.T) NatsTestServer {
	s := NatsTestServer{
		server.New(&server.Options{Host: "localhost", Port: natsPort}),
		false,
		nats.Options{
			Url: fmt.Sprintf("nats://localhost:%d", natsPort),
		},
	}

	go s.srv.Start()

	for i := 0; i != 5; i++ {
		// let the goroutine start to listen
		runtime.Gosched()

		natsConn, err := s.ConnOptions.Connect()
		if err == nil {
			natsConn.Close()
			s.ready = true
			break
		}
	}
	if !s.ready {
		t.Fatalf("Unable to start the server properly (cannot connect to it)")
	}

	return s
}

// IsReady returns true if the server is ready
func (s NatsTestServer) IsReady() bool {
	return s.ready
}

// Connect returns a new client connection to the server
func (s NatsTestServer) Connect(t *testing.T) *nats.Conn {
	natsConn, err := s.ConnOptions.Connect()

	if err != nil {
		t.Fatalf("Cannot connect to nats: %s", err)
		return nil
	}
	return natsConn
}

// Shutdown stops the server
func (s NatsTestServer) Shutdown() {
	s.srv.Shutdown()
}
