package handlers

import (
	"fmt"
	"net/url"
	"unicode"
)

func appendQuery(rawURL string, values ...interface{}) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	newURL := &url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}

	q := u.Query()
	for i := 0; i+1 < len(values); i += 2 {
		key := fmt.Sprint(values[i])
		val := fmt.Sprint(values[i+1])
		q.Set(key, val) // replaces existing or adds new
	}

	newURL.RawQuery = q.Encode()
	return newURL.String()
}

func sanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	isAlphanumeric := func(s string) bool {
		for _, r := range s {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return false
			}
		}
		return true
	}

	newURL := &url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}

	q := url.Values{}
	for key, val := range u.Query() {
		if !isAlphanumeric(key) {
			continue
		}
		for _, v := range val {
			q.Add(key, v)
		}
	}
	newURL.RawQuery = q.Encode()

	return newURL.String()
}
