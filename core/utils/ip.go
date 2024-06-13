package utils

import (
	"encoding/json"
	"fmt"
	"goProxy/core/db"
	"io"
	"net/http"
	"net/url"

	"github.com/boltdb/bolt"
)

type IPInfo struct {
	Country struct {
		Code string `json:"alpha2_code"`
	} `json:"country"`
	AS struct {
		Num string `json:"number"`
	} `json:"as"`
}

func CheckAbuseIPDB(IP string, apiKey string) (bool, string) {
    fmt.Println("Checking IP: " + IP)
    fmt.Println("Using API Key: " + apiKey)

    queryParams := url.Values{}
    queryParams.Add("ipAddress", IP)
    queryParams.Add("maxAgeInDays", "90")
    queryParams.Add("verbose", "")

    urlStr := "https://api.abuseipdb.com/api/v2/check?" + queryParams.Encode()

    req, _ := http.NewRequest("GET", urlStr, nil)
    req.Header.Add("Key", apiKey)
    req.Header.Add("Accept", "application/json")

    fmt.Println("Requesting: " + urlStr)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err!= nil {
        return false, ""
    }
    defer resp.Body.Close()
    fmt.Println("Response: " + resp.Status)

    body, _ := io.ReadAll(resp.Body)
    var data map[string]interface{}
    json.Unmarshal(body, &data)
    fmt.Println("Data: " + string(body))

    if data["data"].(map[string]interface{})["abuseConfidenceScore"].(float64) > 50 {
        return true, data["data"].(map[string]interface{})["abuseConfidenceScore"].(string)
    }

    return false, ""
}

func GetIpInfo(IP string) (country string, asn string) {

	var ipCountry []byte
	var ipAsn []byte

	db.Instance.DB.View(func(tx *bolt.Tx) error {
		countries := tx.Bucket([]byte("countries"))
		asns := tx.Bucket([]byte("asns"))

		ipCountry = countries.Get([]byte(IP))
		ipAsn = asns.Get([]byte(IP))

		return nil
	})

	//Check if result already in database
	if string(ipCountry) != "" {
		return string(ipCountry), string(ipAsn)
	}

	//If not, request it
	resp, err := http.Get("http://apimon.de/ip/" + IP)
	if err != nil {
		return "UNK", "UNK"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "UNK", "UNK"
	}

	var data IPInfo
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "UNK", "UNK"
	}

	//Write to database for future usage
	updateErr := db.Instance.DB.Update(func(tx *bolt.Tx) error {
		countries := tx.Bucket([]byte("countries"))
		asns := tx.Bucket([]byte("asns"))

		// Store a value.
		err = countries.Put([]byte(IP), []byte(data.Country.Code))
		if err != nil {
			return err
		}
		err = asns.Put([]byte(IP), []byte(data.AS.Num))
		if err != nil {
			return err
		}

		return nil
	})
	if updateErr != nil {
		return "UNK", "UNK"
	}

	return data.Country.Code, data.AS.Num
}

func GetOwnIP() (string, error) {
	resp, err := http.Get("http://checkip.amazonaws.com")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip[:len(ip)-1]), nil
}
