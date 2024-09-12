package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func GetAuthorizationToken(h http.Header) string {
	auth := h.Get("Authorization")
	splitResult := strings.Split(auth, " ")
	if len(splitResult) > 1 {
		return splitResult[1]
	}
	return ""
}

func HttpCommon(method, url string, header map[string][]string, reader io.Reader) (int, []byte, error) {
	header["Content-Type"] = []string{"application/json"}
	header["User-Agent"] = []string{"Seafile Server"}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	req.Header = header

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		errMsg := parseErrorMessage(rsp.Body)
		return rsp.StatusCode, errMsg, fmt.Errorf("bad response %d for %s", rsp.StatusCode, url)
	}

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return rsp.StatusCode, nil, err
	}

	return http.StatusOK, body, nil
}

func parseErrorMessage(r io.Reader) []byte {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	var objs map[string]string
	err = json.Unmarshal(body, &objs)
	if err != nil {
		return body
	}
	errMsg, ok := objs["error_msg"]
	if ok {
		return []byte(errMsg)
	}

	return body
}
