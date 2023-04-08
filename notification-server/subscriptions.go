package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	chanBufSize = 10
)

// clients is a map from client id to Client structs.
// It contains all current connected clients. Each client is identified by 64-bit ID.
var clients map[uint64]*Client
var clientsMutex sync.RWMutex

// Use atomic operation to increase this value.
var nextClientID uint64 = 1

// subscriptions is a map from repo_id to Subscribers struct.
// It's protected by rw mutex.
var subscriptions map[string]*Subscribers
var subMutex sync.RWMutex

// Client contains information about a client.
// Two go routines are associated with each client to handle message reading and writting.
// Messages sent to the client have to be written into WCh, since only one go routine can write to a websocket connection.
type Client struct {
	// The ID of this client
	ID uint64
	// Websocket connection.
	conn *websocket.Conn
	// Connections do not support concurrent writers. Protect write with a mutex.
	connMutex sync.Mutex

	// WCh is used to write messages to a client.
	// The structs written into the channel will be converted to JSON and sent to client.
	WCh chan interface{}

	// Repos is the repos this client subscribed to.
	Repos      map[string]int64
	ReposMutex sync.Mutex
	// Alive is the last time received pong.
	Alive time.Time
	// ConnClosed indicates whether the client's connection has been closed
	ConnClosed bool
	// Addr is the address of client.
	Addr string
	// User is the user of client.
	User string
}

// Subscribers contains the clients who subscribe to a repo's notifications.
type Subscribers struct {
	// Clients is a map from client id to Client struct, protected by rw mutex.
	Clients map[uint64]*Client
	Mutex   sync.RWMutex
}

// Init inits clients and subscriptions.
func Init() {
	clients = make(map[uint64]*Client)
	subscriptions = make(map[string]*Subscribers)
}

// NewClient creates a new client.
func NewClient(conn *websocket.Conn, addr string) *Client {
	client := new(Client)
	client.ID = atomic.AddUint64(&nextClientID, 1)
	client.conn = conn
	client.WCh = make(chan interface{}, chanBufSize)
	client.Repos = make(map[string]int64)
	client.Alive = time.Now()
	client.Addr = addr

	return client
}

// Register adds the client to the list of clients.
func RegisterClient(client *Client) {
	clientsMutex.Lock()
	clients[client.ID] = client
	clientsMutex.Unlock()
}

// Unregister deletes the client from the list of clients.
func UnregisterClient(client *Client) {
	clientsMutex.Lock()
	delete(clients, client.ID)
	clientsMutex.Unlock()
}

func newSubscribers(client *Client) *Subscribers {
	subscribers := new(Subscribers)
	subscribers.Clients = make(map[uint64]*Client)
	subscribers.Clients[client.ID] = client

	return subscribers
}
