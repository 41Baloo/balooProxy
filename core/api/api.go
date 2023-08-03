package api

import (
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"goProxy/core/utils"

	"github.com/gofiber/fiber/v2"
)

var ()

func Process(c *fiber.Ctx, domainData domains.DomainData) bool {

	if c.GetReqHeaders()["Proxy-Secret"] != proxy.APISecret {
		return false
	}

	var apiRequest API_REQUEST
	err := json.Unmarshal(c.Body(), &apiRequest)
	if err != nil {
		APIResponse(c, false, map[string]interface{}{
			"ERROR": ERR_JSON_READ_FAILED,
		})
		return true
	}

	//Proxy specific requests
	if apiRequest.Domain == "" {
		switch apiRequest.Action {
		case "GET_PROXY_STATS":
			APIResponse(c, true, map[string]interface{}{
				"CPU_USAGE": proxy.CpuUsage,
				"RAM_USAGE": proxy.RamUsage,
			})
		case "GET_PROXY_STATS_CPU_USAGE":
			APIResponse(c, true, map[string]interface{}{
				"CPU_USAGE": proxy.CpuUsage,
			})
		case "GET_PROXY_STATS_RAM_USAGE":
			APIResponse(c, true, map[string]interface{}{
				"RAM_USAGE": proxy.RamUsage,
			})
		case "GET_IP_REQUESTS":
			firewall.Mutex.Lock()
			ipsAll := firewall.AccessIps
			ipsCookie := firewall.AccessIpsCookie
			firewall.Mutex.Unlock()

			APIResponse(c, true, map[string]interface{}{
				"TOTAL_IP_REQUESTS":     ipsAll,
				"CHALLENGE_IP_REQUESTS": ipsCookie,
			})
		//Only returns UNK Fingerprints
		case "GET_FINGERPRINT_REQUESTS":
			firewall.Mutex.Lock()
			ipsFps := firewall.UnkFps
			firewall.Mutex.Unlock()

			APIResponse(c, true, map[string]interface{}{
				"TOTAL_FINGERPRINT_REQUESTS": ipsFps,
			})
		case "GET_IP_CACHE":
			cacheIps := make(map[string]interface{})
			firewall.CacheIps.Range(func(key, value any) bool {
				cacheIps[fmt.Sprint(key)] = value
				return true
			})

			APIResponse(c, true, map[string]interface{}{
				"IP_CACHE": cacheIps,
			})
		// Useful to fill up your ipCache and see how your proxy performs with high memory usage
		case "FILL_IP_CACHE":
			firewall.Mutex.Lock()
			for i := 0; i < 19980; i++ {
				firewall.CacheIps.Store(utils.RandomString(24), utils.RandomString(64))
			}
			firewall.Mutex.Unlock()

			APIResponse(c, true, map[string]interface{}{})
		default:
			APIResponse(c, false, map[string]interface{}{
				"ERROR": ERR_ACTION_NOT_FOUND,
			})
		}
		return true
	}

	apiDomain, ok := domains.DomainsMap.Load(apiRequest.Domain)
	if !ok {
		APIResponse(c, false, map[string]interface{}{
			"ERROR": ERR_DOMAIN_NOT_FOUND,
		})
		return true
	}

	//Domain specific requests
	switch apiRequest.Action {
	case "GET_TOTAL_REQUESTS":
		APIResponse(c, true, map[string]interface{}{
			"TOTAL_REQUESTS": domainData.TotalRequests,
		})
	case "GET_BYPASSED_REQUESTS":
		APIResponse(c, true, map[string]interface{}{
			"BYPASSED_REQUESTS": domainData.BypassedRequests,
		})
	case "GET_TOTAL_REQUESTS_PER_SECOND":
		APIResponse(c, true, map[string]interface{}{
			"TOTAL_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsPerSecond,
		})
	case "GET_BYPASSED_REQUESTS_PER_SECOND":
		APIResponse(c, true, map[string]interface{}{
			"BYPASSED_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsBypassedPerSecond,
		})
	case "GET_FIREWALL_RULES":
		APIResponse(c, true, map[string]interface{}{
			"FIREWALL_RULES": apiDomain.(domains.DomainSettings).RawCustomRules,
		})
	case "GET_CACHE_RULES":
		APIResponse(c, true, map[string]interface{}{
			"CACHE_RULES": apiDomain.(domains.DomainSettings).RawCacheRules,
		})
	// This is still janky since it contains the formatting from the console & also changes size depending on the console size
	case "GET_LOGS":
		APIResponse(c, true, map[string]interface{}{
			"LOGS": domainData.LastLogs,
		})
	default:
		APIResponse(c, false, map[string]interface{}{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
	return true
}

func APIResponse(c *fiber.Ctx, success bool, response map[string]interface{}) {

	apiResponse := API_RESPONSE{
		Success:  success,
		Response: response,
	}

	c.JSON(apiResponse)
}
