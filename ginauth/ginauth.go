package ginauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// BasicToken is the name of the token on the Gin Context if Basic Auth is used
const BasicToken = "BasicToken"

// BearerToken is the name of the token on the Gin Context if Basic Auth is used
const BearerToken = "BearerToken"

// BearerParser is the interface for something that can parse and verify a Bearer Token
type BearerParser interface {
	Realm() string
	ParseAndVerify(bearerToken string) (interface{}, error)
}

func getBearerToken(header http.Header) (string, error) {

	authorization := header.Get("Authorization")
	parts := strings.Split(authorization, " ")
	if len(parts) != 2 {
		return "", errors.New("invalid bearer format [" + authorization + "]")
	}

	return parts[1], nil
}

// BearerHandler extracts the Bearer Token and verifies it via the BearerParser
func BearerHandler(parser BearerParser) gin.HandlerFunc {

	autherr := "Bearer realm=" + parser.Realm()

	return func(c *gin.Context) {

		bearerToken, err := getBearerToken(c.Request.Header)
		if err != nil {
			c.Header("WWW-Authenticate", autherr)
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		token, err := parser.ParseAndVerify(bearerToken)
		if err != nil {
			c.Header("WWW-Authenticate", autherr)
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Set(BearerToken, token)
	}
}

// BasicParser is the interface for something that can parse and verify a Basic Token
type BasicParser interface {
	Realm() string
	ParseAndVerify(user, password string) (interface{}, error)
}

var errMissingAuth = errors.New("basic auth missing or wrong format")

// BasicHandler extracts the Basic Token and verifies it via the BasicParser
func BasicHandler(parser BasicParser) gin.HandlerFunc {
	autherr := "Basic realm=" + parser.Realm()

	return func(c *gin.Context) {

		// Search user in the slice of allowed credentials
		user, pass, ok := c.Request.BasicAuth()
		if !ok {
			c.Header("WWW-Authenticate", autherr)
			c.AbortWithError(http.StatusUnauthorized, errMissingAuth)
			return
		}

		token, err := parser.ParseAndVerify(user, pass)
		if err != nil {
			c.Header("WWW-Authenticate", autherr)
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Set(BasicToken, token)
	}
}
