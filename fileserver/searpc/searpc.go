// Package searpc implements searpc client protocol with unix pipe transport.
package searpc

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
)

// Client represents a connections to the RPC server.
type Client struct {
	// path of the named pipe
	pipePath string
	// RPC service name
	Service string `json:"service"`
	// RPC request
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
// The return value of the RPC function is return as interface{} type.
// The true returned type can be int32, int64, string, struct (object), list of struct (objects) or JSON
func (c *Client) Call(funcname string, params ...interface{}) interface{} {
	// TODO: use reflection to compose requests and parse results.
	var unixAddr *net.UnixAddr
	unixAddr, err := net.ResolveUnixAddr("unix", c.pipePath)
	if err != nil {
		fmt.Printf("failed to resolve unix addr : %v.\n", err)
		return nil
	}

	conn, err := net.DialUnix("unix", nil, unixAddr)
	if err != nil {
		fmt.Printf("failed to dial unix : %v.\n", err)
		return nil
	}
	defer conn.Close()

	var request []interface{}
	request = append(request, funcname)
	request = append(request, params...)
	jsonstr, err := json.Marshal(request)
	if err != nil {
		fmt.Printf("failed to convert object to json : %v\n", err)
	}
	c.Request = string(jsonstr)

	jsonstr, err = json.Marshal(c)
	if err != nil {
		fmt.Printf("failed to convert object to json.\n")
		return nil
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(jsonstr)))
	conn.Write([]byte(header))

	conn.Write([]byte(jsonstr))

	reader := bufio.NewReader(conn)
	buflen := make([]byte, 4)
	_, err = io.ReadFull(reader, buflen)
	if err != nil {
		fmt.Printf("failed to read from rpc server : %v.\n", err)
		return nil
	}
	retlen := binary.LittleEndian.Uint32(buflen)

	msg := make([]byte, retlen)
	_, err = io.ReadFull(reader, msg)
	if err != nil {
		fmt.Printf("failed to read from rpc server : %v.\n", err)
		return nil
	}

	retlist := make(map[string]interface{})
	err = json.Unmarshal(msg, &retlist)
	if err != nil {
		fmt.Printf("failed to parse return data.\n")
		return nil
	}

	if _, ok := retlist["err_code"]; ok {
		fmt.Printf("get error message : %v.\n", retlist["err_msg"])
		return nil
	}

	if _, ok := retlist["ret"]; ok {
		ret := retlist["ret"]
		switch ret.(type) {
		case float64, float32:
			return reflect.ValueOf(ret).Float()
		case int:
			return reflect.ValueOf(ret).Int()
		case string:
			return reflect.ValueOf(ret).String()
		case []interface{}:
			return reflect.ValueOf(ret).Interface()
		case map[string]interface{}:
			return reflect.ValueOf(ret).Interface()
		case nil:
			return nil
		default:
			return nil
		}
	}

	return nil
}
