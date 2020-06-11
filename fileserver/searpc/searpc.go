// Package searpc implements searpc client protocol with unix pipe transport.
package searpc

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// Client represents a connections to the RPC server.
type Client struct {
	// path of the named pipe
	pipePath string
	// RPC service name
	Service string
}

type Request struct {
	Service string `json:"service"`
	Request string `json:"request"`
}

// Init initializes rpc client.
func Init(pipePath string, service string) *Client {
	client := new(Client)
	client.pipePath = pipePath
	client.Service = service

	return client
}

// Call calls the RPC function funcname with variadic parameters.
// The return value of the RPC function is return as interface{} type
// The true returned type can be int32, int64, string, struct (object), list of struct (objects) or JSON
func (c *Client) Call(funcname string, params ...interface{}) (interface{}, error) {
	// TODO: use reflection to compose requests and parse results.
	var unixAddr *net.UnixAddr
	unixAddr, err := net.ResolveUnixAddr("unix", c.pipePath)
	if err != nil {
		fmt.Printf("failed to resolve unix addr : %v.\n", err)
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, unixAddr)
	if err != nil {
		fmt.Printf("failed to dial unix : %v.\n", err)
		return nil, err
	}
	defer conn.Close()

	var request []interface{}
	request = append(request, funcname)
	request = append(request, params...)
	jsonstr, err := json.Marshal(request)
	if err != nil {
		fmt.Printf("failed to encode rpc call to json : %v\n", err)
		return nil, err
	}

	req := new(Request)
	req.Service = c.Service
	req.Request = string(jsonstr)

	jsonstr, err = json.Marshal(req)
	if err != nil {
		fmt.Printf("failed to convert object to json : %v.\n", err)
		return nil, err
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(jsonstr)))
	_, err = conn.Write([]byte(header))
	if err != nil {
		fmt.Printf("Failed to write head to unix socket : %v.\n", err)
		return nil, err
	}

	_, err = conn.Write([]byte(jsonstr))
	if err != nil {
		fmt.Printf("Failed to write body to unix socket : %v.\n", err)
		return nil, err
	}

	reader := bufio.NewReader(conn)
	buflen := make([]byte, 4)
	_, err = io.ReadFull(reader, buflen)
	if err != nil {
		fmt.Printf("failed to read from rpc server : %v.\n", err)
		return nil, err
	}
	retlen := binary.LittleEndian.Uint32(buflen)

	msg := make([]byte, retlen)
	_, err = io.ReadFull(reader, msg)
	if err != nil {
		fmt.Printf("failed to read from rpc server : %v.\n", err)
		return nil, err
	}

	retlist := make(map[string]interface{})
	err = json.Unmarshal(msg, &retlist)
	if err != nil {
		fmt.Printf("failed to decode rpc response : %v.\n", err)
		return nil, err
	}

	if _, ok := retlist["err_code"]; ok {
		fmt.Printf("searpc server returned error : %v.\n", retlist["err_msg"])
		err := fmt.Errorf("%s", retlist["err_msg"])
		return nil, err
	}

	if _, ok := retlist["ret"]; ok {
		ret := retlist["ret"]
		return ret, nil
	}

	err = fmt.Errorf("No value returned")
	return nil, err
}
