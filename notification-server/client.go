package main

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	writeWait = 1 * time.Second
	pongWait  = 5 * time.Second
	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 1 * time.Second

	checkTokenPeriod = 1 * time.Hour
)

// Message is the message communicated between clients and server.
type Message struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type SubList struct {
	Repos []Repo `json:"repos"`
}

type UnsubList struct {
	Repos []Repo `json:"repos"`
}

type Repo struct {
	RepoID string `json:"id"`
	Token  string `json:"jwt_token"`
}

type myClaims struct {
	Exp      int64  `json:"exp"`
	RepoID   string `json:"repo_id"`
	UserName string `json:"username"`
	jwt.RegisteredClaims
}

func (*myClaims) Valid() error {
	return nil
}

func (client *Client) Close() {
	client.conn.Close()
}

func RecoverWrapper(f func()) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic: %v\n%s", err, debug.Stack())
		}
	}()

	f()
}

// HandleMessages connects to the client to process message.
func (client *Client) HandleMessages() {
	// Set keep alive.
	client.conn.SetPongHandler(func(string) error {
		client.Alive = time.Now()
		return nil
	})

	client.ConnCloser.AddRunning(4)
	go RecoverWrapper(client.readMessages)
	go RecoverWrapper(client.writeMessages)
	go RecoverWrapper(client.checkTokenExpired)
	go RecoverWrapper(client.keepAlive)
	client.ConnCloser.Wait()
	client.Close()
	UnregisterClient(client)
	for id := range client.Repos {
		client.unsubscribe(id)
	}
}

func (client *Client) readMessages() {
	conn := client.conn
	defer func() {
		client.ConnCloser.Done()
	}()

	for {
		select {
		case <-client.ConnCloser.HasBeenClosed():
			return
		default:
		}
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			client.ConnCloser.Signal()
			log.Debugf("failed to read json data from client: %s: %v", client.Addr, err)
			return
		}

		err = client.handleMessage(&msg)
		if err != nil {
			client.ConnCloser.Signal()
			log.Debugf("%v", err)
			return
		}
	}
}

func checkToken(tokenString, repoID string) (string, int64, bool) {
	if len(tokenString) == 0 {
		return "", -1, false
	}
	claims := new(myClaims)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if err != nil {
		return "", -1, false
	}

	if !token.Valid {
		return "", -1, false
	}

	now := time.Now()
	if claims.RepoID != repoID || claims.Exp <= now.Unix() {
		return "", -1, false
	}

	return claims.UserName, claims.Exp, true
}

func (client *Client) handleMessage(msg *Message) error {
	content := msg.Content

	if msg.Type == "subscribe" {
		var list SubList
		err := json.Unmarshal(content, &list)
		if err != nil {
			return err
		}
		for _, repo := range list.Repos {
			user, exp, valid := checkToken(repo.Token, repo.RepoID)
			if !valid {
				client.notifJWTExpired(repo.RepoID)
				continue
			}
			client.subscribe(repo.RepoID, user, exp)
		}
	} else if msg.Type == "unsubscribe" {
		var list UnsubList
		err := json.Unmarshal(content, &list)
		if err != nil {
			return err
		}
		for _, r := range list.Repos {
			client.unsubscribe(r.RepoID)
		}
	} else {
		err := fmt.Errorf("recv unexpected type of message: %s", msg.Type)
		return err
	}

	return nil
}

// subscribe subscribes to notifications of repos.
func (client *Client) subscribe(repoID, user string, exp int64) {
	client.User = user

	client.ReposMutex.Lock()
	client.Repos[repoID] = exp
	client.ReposMutex.Unlock()

	subMutex.Lock()
	subscribers, ok := subscriptions[repoID]
	if !ok {
		subscribers = newSubscribers(client)
		subscriptions[repoID] = subscribers
	}
	subMutex.Unlock()

	subscribers.Mutex.Lock()
	subscribers.Clients[client.ID] = client
	subscribers.Mutex.Unlock()
}

func (client *Client) unsubscribe(repoID string) {
	client.ReposMutex.Lock()
	delete(client.Repos, repoID)
	client.ReposMutex.Unlock()

	subMutex.Lock()
	subscribers, ok := subscriptions[repoID]
	if !ok {
		subMutex.Unlock()
		return
	}
	subMutex.Unlock()

	subscribers.Mutex.Lock()
	delete(subscribers.Clients, client.ID)
	subscribers.Mutex.Unlock()

}

func (client *Client) writeMessages() {
	defer func() {
		client.ConnCloser.Done()
	}()

	for {
		select {
		case msg := <-client.WCh:
			client.conn.SetWriteDeadline(time.Now().Add(writeWait))
			client.connMutex.Lock()
			err := client.conn.WriteJSON(msg)
			client.connMutex.Unlock()
			if err != nil {
				client.ConnCloser.Signal()
				log.Debugf("failed to send notification to client: %v", err)
				return
			}
			m, _ := msg.(*Message)
			log.Debugf("send %s event to client %s(%d): %s", m.Type, client.User, client.ID, string(m.Content))
		case <-client.ConnCloser.HasBeenClosed():
			return
		}
	}
}

func (client *Client) keepAlive() {
	defer func() {
		client.ConnCloser.Done()
	}()

	ticker := time.NewTicker(pingPeriod)
	for {
		select {
		case <-ticker.C:
			if time.Since(client.Alive) > pongWait {
				client.ConnCloser.Signal()
				log.Debugf("disconnected because no pong was received for more than %v", pongWait)
				return
			}
			client.conn.SetWriteDeadline(time.Now().Add(writeWait))
			client.connMutex.Lock()
			err := client.conn.WriteMessage(websocket.PingMessage, nil)
			client.connMutex.Unlock()
			if err != nil {
				client.ConnCloser.Signal()
				log.Debugf("failed to send ping message to client: %v", err)
				return
			}
		case <-client.ConnCloser.HasBeenClosed():
			return
		}
	}
}

func (client *Client) checkTokenExpired() {
	defer func() {
		client.ConnCloser.Done()
	}()

	ticker := time.NewTicker(checkTokenPeriod)
	for {
		select {
		case <-ticker.C:
			// unsubscribe will delete repo from client.Repos, we'd better unsubscribe repos later.
			pendingRepos := make(map[string]struct{})
			now := time.Now()
			client.ReposMutex.Lock()
			for repoID, exp := range client.Repos {
				if exp >= now.Unix() {
					continue
				}
				pendingRepos[repoID] = struct{}{}
			}
			client.ReposMutex.Unlock()

			for repoID := range pendingRepos {
				client.unsubscribe(repoID)
				client.notifJWTExpired(repoID)
			}
		case <-client.ConnCloser.HasBeenClosed():
			return
		}
	}
}

func (client *Client) notifJWTExpired(repoID string) {
	msg := new(Message)
	msg.Type = "jwt-expired"
	content := fmt.Sprintf("{\"repo_id\":\"%s\"}", repoID)
	msg.Content = []byte(content)
	client.WCh <- msg
}
