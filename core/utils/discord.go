package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/proxy"
	"net/http"
	"strings"

	quickchartgo "github.com/henomis/quickchart-go"
)

func InitPlaceholders(msg string, domain domains.DomainSettings) string {
	msg = strings.ReplaceAll(msg, "{{domain.name}}", domain.Name)
	msg = strings.ReplaceAll(msg, "{{attack.start}}", domain.RequestLogger[0].Time.Format("15:04:05"))
	msg = strings.ReplaceAll(msg, "{{attack.end}}", domain.RequestLogger[len(domain.RequestLogger)-1].Time.Format("15:04:05"))
	msg = strings.ReplaceAll(msg, "{{proxy.cpu}}", proxy.CpuUsage)
	msg = strings.ReplaceAll(msg, "{{proxy.ram}}", proxy.RamUsage)

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
					Title:       "ProActive Layer 7 Alert",
					Description: description,
					Color:       15158332,
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
		requests := domain.RequestLogger

		allowedData := ""
		totalData := ""
		CpuLoadData := ""

		for _, request := range requests {
			currTime := request.Time.Format("2006-01-02 15:04:05")
			allowedData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Allowed) + `},`
			totalData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Total) + ` },`
			CpuLoadData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.CpuUsage) + ` },`
		}

		allowedData = strings.TrimSuffix(allowedData, ",")
		totalData = strings.TrimSuffix(totalData, ",")
		CpuLoadData = strings.TrimSuffix(CpuLoadData, ",")

		// https://quickchart.io/sandbox/#%7B%22chart%22%3A%22%7B%5Cn%20%20%5C%22type%5C%22%3A%20%5C%22line%5C%22%2C%5Cn%20%20%5C%22data%5C%22%3A%20%7B%5Cn%20%20%20%20%5C%22datasets%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%5C%22fill%5C%22%3A%20false%2C%5Cn%20%20%20%20%20%20%20%20%5C%22spanGaps%5C%22%3A%20false%2C%5Cn%20%20%20%20%20%20%20%20%5C%22lineTension%5C%22%3A%200.3%2C%5Cn%20%20%20%20%20%20%20%20%5C%22data%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A04%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%2070%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A02%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%2057%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A00%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%2045%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%20%20%5D%2C%5Cn%20%20%20%20%20%20%20%20%5C%22type%5C%22%3A%20%5C%22line%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22label%5C%22%3A%20%5C%22Bypassed%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderColor%5C%22%3A%20%5C%22%232cc56f%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22backgroundColor%5C%22%3A%20%5C%22rgba(44%2C%20197%2C%20111%2C%200.5)%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22pointRadius%5C%22%3A%203%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderWidth%5C%22%3A%203%2C%5Cn%20%20%20%20%20%20%20%20%5C%22hidden%5C%22%3A%20false%5Cn%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%5C%22fill%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%5C%22spanGaps%5C%22%3A%20false%2C%5Cn%20%20%20%20%20%20%20%20%5C%22lineTension%5C%22%3A%200.3%2C%5Cn%20%20%20%20%20%20%20%20%5C%22data%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A04%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%20120%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A02%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%2096%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A00%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%2083%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%20%20%5D%2C%5Cn%20%20%20%20%20%20%20%20%5C%22type%5C%22%3A%20%5C%22line%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22label%5C%22%3A%20%5C%22Total%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderColor%5C%22%3A%20%5C%22%23e74c3c%5C%22%2C%5Cn%5Ct%5Ct%5Ct%5Ct%5C%22backgroundColor%5C%22%3A%20getGradientFillHelper('vertical'%2C%20%5B%5C%22rgba(231%2C%2076%2C%2060%2C%200.7)%5C%22%2C%20%5C%22rgba(231%2C%2076%2C%2060%2C%200.3)%5C%22%2C%20%5C%22rgba(231%2C%2076%2C%2060%2C%200.0)%5C%22%5D)%2C%5Cn%20%20%20%20%20%20%20%20%5C%22pointRadius%5C%22%3A%203%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderWidth%5C%22%3A%203%2C%5Cn%20%20%20%20%20%20%20%20%5C%22hidden%5C%22%3A%20false%5Cn%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%5C%22fill%5C%22%3A%20false%2C%5Cn%20%20%20%20%20%20%20%20%5C%22spanGaps%5C%22%3A%20false%2C%5Cn%20%20%20%20%20%20%20%20%5C%22lineTension%5C%22%3A%200.3%2C%5Cn%20%20%20%20%20%20%20%20%5C%22data%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A04%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%20%2030%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A02%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%20%2020%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22x%5C%22%3A%20%5C%222006-01-02%2015%3A00%3A05%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22y%5C%22%3A%20%5C%22%20%2010%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%20%20%5D%2C%5Cn%20%20%20%20%20%20%20%20%5C%22type%5C%22%3A%20%5C%22line%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22label%5C%22%3A%20%5C%22CPU%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderColor%5C%22%3A%20%5C%22%23ac66f5%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%5C%22pointRadius%5C%22%3A%203%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderWidth%5C%22%3A%203%2C%5Cn%20%20%20%20%20%20%20%20%5C%22borderDash%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%20%20%20%205%2C%5Cn%20%20%20%20%20%20%20%20%20%205%5Cn%20%20%20%20%20%20%20%20%5D%2C%5Cn%20%20%20%20%20%20%20%20%5C%22hidden%5C%22%3A%20false%2C%5Cn%20%20%20%20%20%20%20%20%5C%22yAxisID%5C%22%3A%20%5C%22cpu%5C%22%5Cn%20%20%20%20%20%20%7D%5Cn%20%20%20%20%5D%5Cn%20%20%7D%2C%5Cn%20%20%5C%22options%5C%22%3A%20%7B%5Cn%20%20%20%20%5C%22responsive%5C%22%3A%20true%2C%5Cn%20%20%20%20%5C%22legend%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%5C%22position%5C%22%3A%20%5C%22top%5C%22%2C%5Cn%20%20%20%20%20%20%5C%22align%5C%22%3A%20%5C%22center%5C%22%2C%5Cn%20%20%20%20%20%20%5C%22fullWidth%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%5C%22reverse%5C%22%3A%20false%5Cn%20%20%20%20%7D%2C%5Cn%20%20%20%20%5C%22scales%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%5C%22xAxes%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22position%5C%22%3A%20%5C%22bottom%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22type%5C%22%3A%20%5C%22time%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22distribution%5C%22%3A%20%5C%22series%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22gridLines%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22color%5C%22%3A%20%5C%22rgba(221%2C%20221%2C%20221%2C%200.3)%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22angleLines%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22color%5C%22%3A%20%5C%22rgba(221%2C%20221%2C%20221%2C%200.3)%5C%22%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22ticks%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22reverse%5C%22%3A%20false%5Cn%20%20%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%5D%2C%5Cn%20%20%20%20%20%20%5C%22yAxes%5C%22%3A%20%5B%5Cn%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22position%5C%22%3A%20%5C%22left%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22fontStyle%5C%22%3A%20%5C%22bold%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22fontSize%5C%22%3A%2020%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22type%5C%22%3A%20%5C%22linear%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22gridLines%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22color%5C%22%3A%20%5C%22rgba(221%2C%20221%2C%20221%2C%200.3)%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22scaleLabel%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22labelString%5C%22%3A%20%5C%22Requests%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22fontStyle%5C%22%3A%20%5C%22bold%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22fontSize%5C%22%3A%2013%5Cn%20%20%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22id%5C%22%3A%20%5C%22cpu%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22position%5C%22%3A%20%5C%22right%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22ticks%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22beginAtZero%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22max%5C%22%3A%20100%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22stepSize%5C%22%3A%2010%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22gridLines%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22color%5C%22%3A%20%5C%22rgba(221%2C%20221%2C%20221%2C%200.2)%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%7D%2C%5Cn%20%20%20%20%20%20%20%20%20%20%5C%22scaleLabel%5C%22%3A%20%7B%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22display%5C%22%3A%20true%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22labelString%5C%22%3A%20%5C%22CPU%20Load%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22fontStyle%5C%22%3A%20%5C%22bold%5C%22%2C%5Cn%20%20%20%20%20%20%20%20%20%20%20%20%5C%22fontSize%5C%22%3A%2013%5Cn%20%20%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%20%20%7D%5Cn%20%20%20%20%20%20%5D%5Cn%20%20%20%20%7D%5Cn%20%20%7D%5Cn%7D%22%2C%22width%22%3A500%2C%22height%22%3A300%2C%22version%22%3A%222%22%2C%22backgroundColor%22%3A%22%23373737%22%7D
		chartConfig := `{
  "type": "line",
  "data": {
    "datasets": [
      {
        "fill": false,
        "spanGaps": false,
        "lineTension": 0.3,
        "data": [` + allowedData + `],
        "type": "line",
        "label": "Bypassed",
        "borderColor": "#2cc56f",
        "backgroundColor": "rgba(44, 197, 111, 0.5)",
        "pointRadius": 3,
        "borderWidth": 3,
        "hidden": false
      },
      {
        "fill": true,
        "spanGaps": false,
        "lineTension": 0.3,
        "data": [` + totalData + `],
        "type": "line",
        "label": "Total",
        "borderColor": "#e74c3c",
				"backgroundColor": getGradientFillHelper('vertical', ["rgba(231, 76, 60, 0.7)", "rgba(231, 76, 60, 0.3)", "rgba(231, 76, 60, 0.0)"]),
        "pointRadius": 3,
        "borderWidth": 3,
        "hidden": false
      },
      {
        "fill": false,
        "spanGaps": false,
        "lineTension": 0.3,
        "data": [` + CpuLoadData + `],
        "type": "line",
        "label": "CPU",
        "borderColor": "#ac66f5",
        "pointRadius": 3,
        "borderWidth": 3,
        "borderDash": [
          5,
          5
        ],
        "hidden": false,
        "yAxisID": "cpu"
      }
    ]
  },
  "options": {
    "responsive": true,
    "legend": {
      "display": true,
      "position": "top",
      "align": "center",
      "fullWidth": true,
      "reverse": false
    },
    "scales": {
      "xAxes": [
        {
          "display": true,
          "position": "bottom",
          "type": "time",
          "distribution": "series",
          "gridLines": {
            "color": "rgba(150, 150, 150, 0.3)",
          },
          "angleLines": {
            "color": "rgba(150, 150, 150, 0.3)"
          },
          "ticks": {
            "display": true,
            "reverse": false
          }
        }
      ],
      "yAxes": [
        {
          "display": true,
          "position": "left",
          "fontStyle": "bold",
          "fontSize": 20,
          "type": "linear",
          "gridLines": {
            "color": "rgba(120, 120, 120, 0.3)",
          },
          "scaleLabel": {
            "display": true,
            "labelString": "Requests",
            "fontStyle": "bold",
            "fontSize": 13
          }
        },
        {
          "id": "cpu",
          "display": true,
          "position": "right",
          "ticks": {
            "beginAtZero": true,
            "max": 100,
            "stepSize": 10
          },
          "gridLines": {
            "color": "rgba(120, 120, 120, 0.2)",
          },
          "scaleLabel": {
            "display": true,
            "labelString": "CPU Load",
            "fontStyle": "bold",
            "fontSize": 13
          }
        }
      ]
    }
  }
}`
		qc := quickchartgo.New()
		qc.Config = chartConfig
		qc.Width = 500
		qc.Height = 300
		qc.BackgroundColor = "#2B2D31"
		qc.Version = "2.9.4"
		chartUrl, chartErr := qc.GetShortUrl()

		if chartErr == nil {
			webhookContent = Webhook{
				Content:  "",
				Username: domain.DomainWebhooks.Name,
				Avatar:   domain.DomainWebhooks.Avatar,
				Embeds: []WebhookEmbed{
					{
						Title:       "ProActive Layer 7 Graph",
						Description: description,
						Color:       15158332,
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
							Url: chartUrl,
						},
					},
				},
			}
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
