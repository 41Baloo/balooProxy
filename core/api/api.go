package api

import (
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/proxy"
	"goProxy/core/utils"
	"net/http"
	"strings"
)

var ()

func Process(writer http.ResponseWriter, request *http.Request, domain domains.DomainSettings) bool {

	if request.Header.Get("proxy-secret") != proxy.APISecret {
		return false
	}

	apiQuery := request.URL.Query()
	apiQueryDomain := apiQuery.Get("domain")

	apiDomain, ok := domains.DomainsMap.Load(apiQueryDomain)
	if !ok {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success": false, "details":"DOMAIN_NOT_FOUND"}`)
		domains.DomainsMap.Store(request.Host, domain)
		return true
	}

	apiQueryAction := apiQuery.Get("action")
	switch apiQueryAction {
	case "TOTAL_REQUESTS":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"REQUESTS_PER_SECOND":%d}}`, apiDomain.(domains.DomainSettings).TotalRequests)
	case "BYPASSED_REQUESTS":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"REQUESTS_PER_SECOND":%d}}`, apiDomain.(domains.DomainSettings).BypassedRequests)
	case "TOTAL_REQUESTS_PER_SECOND":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"REQUESTS_PER_SECOND":%d}}`, apiDomain.(domains.DomainSettings).RequestsPerSecond)
	case "BYPASSED_REQUESTS_PER_SECOND":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"REQUESTS_PER_SECOND":%d}}`, apiDomain.(domains.DomainSettings).RequestsBypassedPerSecond)
	case "PROXY_STATS":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"CPU_USAGE":"%s","RAM_USAGE": "%s"}}`, proxy.CpuUsage, proxy.RamUsage)
	case "PROXY_STATS_CPU_USAGE":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"CPU_USAGE":"%s"}}`, proxy.CpuUsage)
	case "PROXY_STATS_RAM_USAGE":
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":true,"results":{"RAM_USAGE":"%s"}}`, proxy.RamUsage)
	case "GET_FIREWALL_RULES":
		writer.Header().Set("Content-Type", "application/json")
		allRules := ``
		for _, rule := range apiDomain.(domains.DomainSettings).RawCustomRules {
			allRules += `{"expression":"` + utils.JsonEscape(rule.Expression) + `", "action":"` + utils.JsonEscape(rule.Action) + `"},`
		}
		allRules = strings.TrimSuffix(allRules, ",")
		fmt.Fprintf(writer, `{"success":true,"results":{"RULES":[%s]}}`, allRules)
	case "GET_CACHE_RULES":
		writer.Header().Set("Content-Type", "application/json")
		allRules := ``
		for _, rule := range apiDomain.(domains.DomainSettings).RawCacheRules {
			allRules += `{"expression":"` + utils.JsonEscape(rule.Expression) + `", "action":"` + utils.JsonEscape(rule.Action) + `"},`
		}
		allRules = strings.TrimSuffix(allRules, ",")
		fmt.Fprintf(writer, `{"success":true,"results":{"RULES":[%s]}}`, allRules)
	default:
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"success":false,"details":"ACTION_NOT_FOUND"}`)
	}

	domains.DomainsMap.Store(request.Host, domain)
	return true
}
