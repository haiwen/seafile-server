// Package searpc implements searpc client protocol with unix pipe transport.
package searpc

// Client represents a connections to the RPC server.
type Client struct {
	// path of the named pipe
	pipePath string
	// RPC service name
	service string
}

// Call calls the RPC function funcname with variadic parameters.
// The return value of the RPC function is return as interface{} type.
// The true returned type can be int32, int64, string, struct (object), list of struct (objects) or JSON
func (c *Client) Call(funcname string, params ...interface{}) interface{} {
	// TODO: use reflection to compose requests and parse results.
	return nil
}
