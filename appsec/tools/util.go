package tools

import "net/http"

// CheckAccountID returns the request with accountSwitchKey query
func CheckAccountID(accountID interface{}, req *http.Request) {
	if accountID != nil {
		switch id := accountID.(type) {
		case string:
			req.URL.Query().Add("accountSwitchKey", id)
		}
	}
}
