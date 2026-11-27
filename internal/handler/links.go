package handler

import (
	"errors"
	"net/url"
)

// spaBase is the path the SPA is built for (vite.config.ts base).
const spaBase = "/accounts/"

// publicLink returns spaBase with one query parameter, on the scheme and host
// of issuer (JWT_ISSUER). The path of issuer is not used.
func publicLink(issuer, param, value string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", errors.New("JWT_ISSUER must be an http or https URL with a host")
	}
	q := url.Values{}
	q.Set(param, value)
	return u.Scheme + "://" + u.Host + spaBase + "?" + q.Encode(), nil
}
