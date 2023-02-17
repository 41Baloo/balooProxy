package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/proxy"
	"io"
	"net/http"
	"strings"
)

func InitPlaceholders(msg string, domain domains.DomainSettings) string {
	msg = strings.ReplaceAll(msg, "{{domain.name}}", domain.Name)
	msg = strings.ReplaceAll(msg, "{{attack.start}}", domain.RequestLogger[0].Time.Format("15:04:05"))
	msg = strings.ReplaceAll(msg, "{{attack.end}}", domain.RequestLogger[len(domain.RequestLogger)-1].Time.Format("15:04:05"))
	msg = strings.ReplaceAll(msg, "{{proxy.cpu}}", proxy.CpuUsage)
	msg = strings.ReplaceAll(msg, "{{proxy.ram}}", proxy.RamUsage)

	return msg

	return msg
}

func SendWebhook(domain domains.DomainSettings, notificationType int) {

	if domain.DomainWebhooks.URL == "" {
		return
	}

	webhookContent := Webhook{}

	switch notificationType {
	case 0:

		description := InitPlaceholders(domain.DomainWebhooks.AttackStartMsg, domain)

		webhookContent = Webhook{
			Content:  "",
			Username: domain.DomainWebhooks.Name,
			Avatar:   domain.DomainWebhooks.Avatar,
			Embeds: []WebhookEmbed{
				{
					Title:       "DDoS Alert",
					Description: description,
					Color:       5814783,
					Fields: []WebhookField{
						{
							Name:  "Total requests per second",
							Value: "```\n" + fmt.Sprint(domain.RequestsPerSecond) + "\n```",
						},
						{
							Name:  "Allowed requests per second",
							Value: "```\n" + fmt.Sprint(domain.RequestsBypassedPerSecond) + "\n```",
						},
					},
				},
			},
		}
	case 1:

		description := InitPlaceholders(domain.DomainWebhooks.AttackStopMsg, domain)

		allowedData := "["
		totalData := "["

		requests := domain.RequestLogger

		for _, request := range requests {
			currTime := request.Time.Format("2006-01-02 15:04:05")
			allowedData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Allowed) + `},`
			totalData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Total) + ` },`
		}

		allowedData = strings.TrimSuffix(allowedData, ",")
		totalData = strings.TrimSuffix(totalData, ",")

		allowedData += "]"
		totalData += "]"

		//panic(allowedData + "\n" + totalData)

		//imageUrl := "https://quickchart.io/chart?c=" + url.QueryEscape("{\"type\": \"line\",\"data\": {\"datasets\": [{\"label\": \"Allowed\",\"backgroundColor\": \"rgba(35, 159, 217, 0.5)\",\"borderColor\": \"rgb(35, 159, 217)\",\"fill\": false,\"data\": "+allowedData+"},{\"label\": \"Total\",\"backgroundColor\": \"rgba(100, 100, 100, 0.5)\",\"borderColor\": \"rgb(100, 100, 100)\",\"fill\": false,\"data\": "+totalData+"}]},\"options\": {\"responsive\": true,\"title\": {\"display\": true,\"text\": \"Attack Details\"},\"scales\": {\"xAxes\": [{\"type\": \"time\",\"display\": true,\"scaleLabel\": {\"display\": true,\"labelString\": \"Time\"},\"ticks\": {\"major\": {\"enabled\": true}}}],\"yAxes\": [{\"display\": true,\"scaleLabel\": {\"display\": true,\"labelString\": \"Requests\"}}]}}}")

		jsonStr := `{"chart":{"type":"line","data":{"datasets":[{"label":"Allowed","backgroundColor":"rgba(35, 159, 217, 0.5)","borderColor":"rgb(35, 159, 217)","fill":false,"data":` + allowedData + `},{"label":"Total","backgroundColor":"rgba(100, 100, 100, 0.5)","borderColor":"rgb(100, 100, 100)","fill":false,"data":` + totalData + `}]},"options":{"responsive":true,"title":{"display":true,"text":"Attack Details"},"scales":{"xAxes":[{"type":"time","display":true,"scaleLabel":{"display":true,"labelString":"Time"},"ticks":{"major":{"enabled":true}}}],"yAxes":[{"display":true,"scaleLabel":{"display":true,"labelString":"Requests"}}]}}}}`

		client := &http.Client{}
		req, reqErr := http.NewRequest("POST", "https://quickchart.io/chart/create", bytes.NewBuffer([]byte(jsonStr)))
		if reqErr != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, respErr := client.Do(req)
		defer resp.Body.Close()
		if respErr != nil {
			return
		}

		body, bodyErr := io.ReadAll(resp.Body)
		if bodyErr != nil {
			return
		}

		var chartResp QuickchartResponse
		json.Unmarshal(body, &chartResp)

		webhookContent = Webhook{
			Content:  "",
			Username: domain.DomainWebhooks.Name,
			Avatar:   domain.DomainWebhooks.Avatar,
			Embeds: []WebhookEmbed{
				{
					Title:       "DDoS Alert",
					Description: description,
					Color:       5814783,
					Fields: []WebhookField{
						{
							Name:  "Peak total requests per second",
							Value: "```\n" + fmt.Sprint(domain.PeakRequestsPerSecond) + "\n```",
						},
						{
							Name:  "Peak allowed requests per second",
							Value: "```\n" + fmt.Sprint(domain.PeakRequestsBypassedPerSecond) + "\n```",
						},
					},
					Image: WebhookImage{
						Url: chartResp.Url,
					},
				},
			},
		}

		domain.PeakRequestsPerSecond = 0
		domain.PeakRequestsBypassedPerSecond = 0
		domain.RequestLogger = []domains.RequestLog{}

		domains.DomainsMap.Store(domain.Name, domain)
	}

	webhookPayload, err := json.Marshal(webhookContent)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", domain.DomainWebhooks.URL, bytes.NewBuffer(webhookPayload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	client.Do(req)
}

type Webhook struct {
	Content  string         `json:"content"`
	Embeds   []WebhookEmbed `json:"embeds"`
	Username string         `json:"username"`
	Avatar   string         `json:"avatar_url"`
}

type WebhookEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []WebhookField `json:"fields"`
	Image       WebhookImage   `json:"image"`
}

type WebhookField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WebhookImage struct {
	Url string `json:"url"`
}

type QuickchartResponse struct {
	Success string `json:"success"`
	Url     string `json:"url"`
}
