package utils

import (
	"encoding/json"
	"goProxy/core/db"
	"io/ioutil"
	"net/http"

	"github.com/boltdb/bolt"
)

type IpInfo struct {
	Country struct {
		Code string `json:"alpha2_code"`
	} `json:"country"`
	AS struct {
		Num string `json:"number"`
	} `json:"as"`
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "UNK", "UNK"
	}

	var data IpInfo
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

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip[:len(ip)-1]), nil
}
