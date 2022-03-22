// Package searpc implements searpc client protocol with unix pipe transport.
package searpc

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"context"
	"log"
	"time"
	"sync"
)

const PoolSize = 10
const TimeOut = 30

// Client represents a connections to the RPC server.
type Client struct {
	// path of the named pipe
	pipePath string
	// RPC service name
	Service string
	pool *Pool
}

type request struct {
	Service string `json:"service"`
	Request string `json:"request"`
}

type Pool struct {
	m sync.Mutex
	resource chan *net.UnixConn
	capacity int
	counter int
	factory func() (*net.UnixConn, error)
}

func NewPool(fn func() (*net.UnixConn, error), size int) (*Pool) {
	if size <= 0 {
		return nil
	}
	return &Pool {
		factory: fn,
		resource: make(chan *net.UnixConn, size),
		capacity: size,
		counter: 0,
	}
}

func (p *Pool) Get() (*net.UnixConn, error) {
	p.m.Lock()
	defer p.m.Unlock()

	if p.counter >= PoolSize {
		conn := <-p.resource
		return conn, nil
	}

	select {
	case conn := <-p.resource:
		return conn, nil
	default:
		log.Printf("create new one")
		p.counter++
		return p.factory()
	}
}

func (p *Pool) Put(conn *net.UnixConn, drop bool) {
	if drop {
		log.Printf("drop connection")
		conn.Close()
		p.counter--
		return
	}

	select {
	case p.resource <- conn:
	default:
		log.Printf("pool full, close it")
		conn.Close()
		p.counter--
	}
}

// Init initializes rpc client.
func Init(pipePath string, service string) *Client {
	client := new(Client)
	client.pipePath = pipePath
	client.Service = service

	client.pool = NewPool(func () (*net.UnixConn, error) {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), TimeOut * time.Second)
		defer cancel()

		var unixAddr *net.UnixAddr
		unixAddr, err := net.ResolveUnixAddr("unix", pipePath)
		if err != nil {
			err := fmt.Errorf("failed to resolve unix addr when calling rpc : %v", err)
			return nil, err
		}
		d.LocalAddr = nil
		conn, err := d.DialContext(ctx, "unix", unixAddr.String())
		if err != nil {
			err := fmt.Errorf("failed to dial unix when calling rpc : %v", err)
			return nil, err
		}
		return conn.(*net.UnixConn), err
	}, PoolSize)

	return client
}

// Call calls the RPC function funcname with variadic parameters.
// The return value of the RPC function is return as interface{} type
// The true returned type can be int32, int64, string, struct (object), list of struct (objects) or JSON
func (c *Client) Call(funcname string, params ...interface{}) (interface{}, error) {
	// TODO: use reflection to compose requests and parse results.

	conn, err := c.pool.Get()
	if err != nil {
		err := fmt.Errorf("failed to get conn from pool: %v.", err)
		return  nil, err
	}
	var isDrop bool
	defer c.pool.Put(conn, isDrop)

	var req []interface{}
	req = append(req, funcname)
	req = append(req, params...)
	jsonstr, err := json.Marshal(req)
	if err != nil {
		err := fmt.Errorf("failed to encode rpc call to json : %v", err)
		return nil, err
	}

	reqHeader := new(request)
	reqHeader.Service = c.Service
	reqHeader.Request = string(jsonstr)

	jsonstr, err = json.Marshal(reqHeader)
	if err != nil {
		err := fmt.Errorf("failed to convert object to json : %v", err)
		return nil, err
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(jsonstr)))

	conn.SetDeadline(time.Now().Add(TimeOut * time.Second))
	_, err = conn.Write([]byte(header))
	if err != nil {
		isDrop = true
		err := fmt.Errorf("Failed to write rpc request header : %v", err)
		return nil, err
	}
	_, err = conn.Write([]byte(jsonstr))
	if err != nil {
		isDrop = true
		err := fmt.Errorf("Failed to write rpc request body : %v", err)
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(TimeOut * time.Second))
	reader := bufio.NewReader(conn)
	buflen := make([]byte, 4)
	_, err = io.ReadFull(reader, buflen)
	if err != nil {
		isDrop = true
		err := fmt.Errorf("failed to read response header from rpc server : %v", err)
		return nil, err
	}
	retlen := binary.LittleEndian.Uint32(buflen)

	msg := make([]byte, retlen)
	_, err = io.ReadFull(reader, msg)
	if err != nil {
		isDrop = true
		err := fmt.Errorf("failed to read response body from rpc server : %v", err)
		return nil, err
	}

	conn.SetDeadline(time.Time{})

	retlist := make(map[string]interface{})
	err = json.Unmarshal(msg, &retlist)

	if err != nil {
		isDrop = true
		err := fmt.Errorf("failed to decode rpc response : %v", err)
		return nil, err
	}

	if _, ok := retlist["err_code"]; ok {
		err := fmt.Errorf("searpc server returned error : %v", retlist["err_msg"])
		return nil, err
	}

	if _, ok := retlist["ret"]; ok {
		ret := retlist["ret"]
		return ret, nil
	}

	err = fmt.Errorf("No value returned")
	return nil, err
}
