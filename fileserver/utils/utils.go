package utils

import (
	"github.com/google/uuid"
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
