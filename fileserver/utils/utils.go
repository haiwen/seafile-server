package utils

import (
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/haiwen/seafile-server/fileserver/option"
)

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func IsObjectIDValid(objID string) bool {
	if len(objID) != 40 {
		return false
	}
	for i := 0; i < len(objID); i++ {
		c := objID[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

type SeahubClaims struct {
	Exp        int64 `json:"exp"`
	IsInternal bool  `json:"is_internal"`
	jwt.RegisteredClaims
}

func (*SeahubClaims) Valid() error {
	return nil
}

func GenSeahubJWTToken() (string, error) {
	claims := new(SeahubClaims)
	claims.Exp = time.Now().Add(time.Second * 300).Unix()
	claims.IsInternal = true

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString([]byte(option.JWTPrivateKey))
	if err != nil {
		err := fmt.Errorf("failed to gen seahub jwt token: %w", err)
		return "", err
	}

	return tokenString, nil
}

type MyClaims struct {
	Exp      int64  `json:"exp"`
	RepoID   string `json:"repo_id"`
	UserName string `json:"username"`
	jwt.RegisteredClaims
}

func (*MyClaims) Valid() error {
	return nil
}

func GenNotifJWTToken(repoID, user string, exp int64) (string, error) {
	claims := new(MyClaims)
	claims.Exp = exp
	claims.RepoID = repoID
	claims.UserName = user

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString([]byte(option.JWTPrivateKey))
	if err != nil {
		err := fmt.Errorf("failed to gen jwt token for repo %s: %w", repoID, err)
		return "", err
	}

	return tokenString, nil
}
