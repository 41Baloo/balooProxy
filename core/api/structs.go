package api

const (
	ERR_DOMAIN_NOT_FOUND = "ERR_DOMAIN_NOT_FOUND"
	ERR_ACTION_NOT_FOUND = "ERR_ACTION_NOT_FOUND"
	ERR_BODY_READ_FAILED = "ERR_BODY_READ_FAILED"
	ERR_JSON_READ_FAILED = "ERR_JSON_READ_FAILED"
)

type API_REQUEST struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
}

type API_RESPONSE struct {
	Success  bool                   `json:"success"`
	Response map[string]interface{} `json:"results"`
}
