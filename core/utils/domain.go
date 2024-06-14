package utils

import (
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"io/ioutil"
	"strings"
)

func AddDomain() {
	fmt.Println("[ " + PrimaryColor("No Domain Configurations Found") + " ]")
	fmt.Println("[ " + PrimaryColor("Configure New Domains In The Config.json") + " ]")
	fmt.Println("")
	gDomain := domains.Domain{
		Name:        AskString("What Is The Name Of Your Domain (eg. \"example.com\")", "example.com"),
		Backend:     AskString("What Is The Backed/Server The Proxy Should Proxy To?", "1.1.1.1"),
		Scheme:      strings.ToLower(AskString("What Scheme Should The Proxy Use To Communicate With Your Backend? (http/https)", "http")),
		Certificate: AskString("What Is The Path To The SSL Certificate For Your Domain? (Leave Empty If You Are Using The Proxy Behind Cloudflare)", ""),
		Key:         AskString("What Is The Path To The SSL Key For Your Domain? (Leave Empty If You Are Using The Proxy Behind Cloudflare)", ""),
		Webhook: domains.WebhookSettings{
			URL:            AskString("What Is The Url For Your Discord Webhook? (Leave Empty If You Do Not Want One)", ""),
			Name:           AskString("What Is The Name For Your Discord Webhook? (Leave Empty If You Do Not Want One)", ""),
			Avatar:         AskString("What Is The Url For Your Discord Webhook Avatar? (Leave Empty If You Do Not Want One)", ""),
			AttackStartMsg: AskString("What Is The Message Your Webhook Should Send When Your Website Is Under Attack?", ""),
			AttackStopMsg:  AskString("What Is The Message Your Webhook Should Send When Your Website Is No Longer Under Attack?", ""),
		},
		FirewallRules:       []domains.JsonRule{},
		BypassStage1:        AskInt("At How Many Bypassing Requests Per Second Would You Like To Activate Stage 2?", 75),
		BypassStage2:        AskInt("At How Many Bypassing Requests Per Second Would You Like To Activate Stage 3?", 250),
		DisableBypassStage3: AskInt("How Many Bypassing Requests Per Second Are Low Enough To Disable Stage 3?", 100),
		DisableRawStage3:    AskInt("How Many Requests Per Second Are Low Enough To Disable Stage 3? (Bypassing Requests Still Have To Be Low Enough)", 250),
		DisableBypassStage2: AskInt("How Many Bypassing Requests Per Second Are Low Enough To Disable Stage 2?", 50),
		DisableRawStage2:    AskInt("How Many Requests Per Second Are Low Enough To Disable Stage 2? (Bypassing Requests Still Have To Be Low Enough)", 75),
	}

	domains.Config.Domains = append(domains.Config.Domains, gDomain)

	jsonConfig, err := json.Marshal(domains.Config)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("config.json", jsonConfig, 0644)
	if err != nil {
		panic(err)
	}
}
