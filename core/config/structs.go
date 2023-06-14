package config

type GLOBAL_PROXY_VERSIONS struct {
	LastVersion   float64 `json:"last_version"`
	StableVersion float64 `json:"stable_version"`
	Download      string  `json:"download"`
}
