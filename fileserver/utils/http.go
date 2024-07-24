package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

var HttpReqContext, HttpReqCancel = context.WithCancel(context.Background())

func HttpCommon(method, url string, header map[string][]string, reader io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(HttpReqContext, method, url, reader)
	if err != nil {
		return -1, nil, err
	}
	req.Header = header

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusNotFound {
		return rsp.StatusCode, nil, fmt.Errorf("url %s not found", url)
	}
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return rsp.StatusCode, nil, err
	}

	return rsp.StatusCode, body, nil
}
