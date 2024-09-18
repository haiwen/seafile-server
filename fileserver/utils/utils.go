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

type MyClaims struct {
	Exp        int64  `json:"exp"`
	RepoID     string `json:"repo_id,omitempty"`
	UserName   string `json:"username,omitempty"`
	IsInternal bool   `json:"is_internal,omitempty"`
	jwt.RegisteredClaims
}

func (*MyClaims) Valid() error {
	return nil
}

func GenJWTToken(repoID, user string, isInternal bool) (string, error) {
	claims := new(MyClaims)
	if isInternal {
		claims.Exp = time.Now().Add(time.Second * 300).Unix()
		claims.IsInternal = true
	} else {
		claims.Exp = time.Now().Add(time.Hour * 72).Unix()
		claims.RepoID = repoID
		claims.UserName = user
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString([]byte(option.PrivateKey))
	if err != nil {
		err := fmt.Errorf("failed to gen jwt token for repo %s", repoID)
		return "", err
	}

	return tokenString, nil
}
