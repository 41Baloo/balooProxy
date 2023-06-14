package api

import (
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"io"
	"net/http"
)

var ()

func Process(writer http.ResponseWriter, request *http.Request, domainData domains.DomainData) bool {

	if request.Header.Get("proxy-secret") != proxy.APISecret {
		return false
	}

	reqBody, err := io.ReadAll(request.Body)
	if err != nil {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_BODY_READ_FAILED,
		})
	}

	defer request.Body.Close()

	var apiRequest API_REQUEST
	err = json.Unmarshal(reqBody, &apiRequest)
	if err != nil {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_JSON_READ_FAILED,
		})
		return true
	}

	//Proxy specific requests
	if apiRequest.Domain == "" {
		switch apiRequest.Action {
		case "GET_PROXY_STATS":
			APIResponse(writer, true, map[string]interface{}{
				"CPU_USAGE": proxy.CpuUsage,
				"RAM_USAGE": proxy.RamUsage,
			})
		case "GET_PROXY_STATS_CPU_USAGE":
			APIResponse(writer, true, map[string]interface{}{
				"CPU_USAGE": proxy.CpuUsage,
			})
		case "GET_PROXY_STATS_RAM_USAGE":
			APIResponse(writer, true, map[string]interface{}{
				"RAM_USAGE": proxy.RamUsage,
			})
		case "GET_IP_REQUESTS":
			firewall.Mutex.Lock()
			ipsAll := firewall.AccessIps
			ipsCookie := firewall.AccessIpsCookie
			firewall.Mutex.Unlock()

			APIResponse(writer, true, map[string]interface{}{
				"TOTAL_IP_REQUESTS":     ipsAll,
				"CHALLENGE_IP_REQUESTS": ipsCookie,
			})
		//Only returns UNK Fingerprints
		case "GET_FINGERPRINT_REQUESTS":
			firewall.Mutex.Lock()
			ipsFps := firewall.UnkFps
			firewall.Mutex.Unlock()

			APIResponse(writer, true, map[string]interface{}{
				"TOTAL_FINGERPRINT_REQUESTS": ipsFps,
			})
		default:
			APIResponse(writer, false, map[string]interface{}{
				"ERROR": ERR_ACTION_NOT_FOUND,
			})
		}
		return true
	}

	apiDomain, ok := domains.DomainsMap.Load(apiRequest.Domain)
	if !ok {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_DOMAIN_NOT_FOUND,
		})
		return true
	}

	//Domain specific requests
	switch apiRequest.Action {
	case "GET_TOTAL_REQUESTS":
		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_REQUESTS": domainData.TotalRequests,
		})
	case "GET_BYPASSED_REQUESTS":
		APIResponse(writer, true, map[string]interface{}{
			"BYPASSED_REQUESTS": domainData.BypassedRequests,
		})
	case "GET_TOTAL_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsPerSecond,
		})
	case "GET_BYPASSED_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]interface{}{
			"BYPASSED_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsBypassedPerSecond,
		})
	case "GET_FIREWALL_RULES":
		APIResponse(writer, true, map[string]interface{}{
			"FIREWALL_RULES": apiDomain.(domains.DomainSettings).RawCustomRules,
		})
	case "GET_CACHE_RULES":
		APIResponse(writer, true, map[string]interface{}{
			"CACHE_RULES": apiDomain.(domains.DomainSettings).RawCacheRules,
		})
	default:
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
	return true
}

func APIResponse(writer http.ResponseWriter, success bool, response map[string]interface{}) error {

	writer.Header().Set("Content-Type", "application/json")

	apiResponse := API_RESPONSE{
		Success:  success,
		Response: response,
	}

	jsonResponse, err := json.Marshal(apiResponse)
	if err != nil {
		return err
	}

	fmt.Fprint(writer, string(jsonResponse))
	return nil
}
