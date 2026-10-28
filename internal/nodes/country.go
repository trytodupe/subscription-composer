package nodes

import (
	"errors"
	"strings"
	"unicode"
)

var regions = map[string]string{
	"JP": "JP", "JAPAN": "JP", "JAPANESE": "JP", "TOKYO": "JP", "OSAKA": "JP", "日本": "JP", "东京": "JP", "東京": "JP",
	"HK": "HK", "HONGKONG": "HK", "HONG": "HK", "香港": "HK",
	"US": "US", "USA": "US", "UNITEDSTATES": "US", "AMERICA": "US", "NEWYORK": "US", "LOSANGELES": "US", "美国": "US", "美國": "US",
	"TW": "TW", "TAIWAN": "TW", "TAIPEI": "TW", "台湾": "TW", "臺灣": "TW",
	"SG": "SG", "SINGAPORE": "SG", "SINGAPURA": "SG", "新加坡": "SG",
	"DE": "DE", "GERMANY": "DE", "FRANKFURT": "DE", "德国": "DE", "德國": "DE",
	"GB": "GB", "UK": "GB", "BRITAIN": "GB", "LONDON": "GB", "UNITEDKINGDOM": "GB", "英国": "GB", "英國": "GB",
	"KR": "KR", "KOREA": "KR", "SOUTHKOREA": "KR", "SEOUL": "KR", "韩国": "KR", "韓國": "KR",
}

func countryFor(sourceID, name string, overrides map[string]string) (string, error) {
	if value, ok := overrides[sourceID+"/"+name]; ok {
		return normalizeCountry(value)
	}
	if value, ok := overrides[name]; ok {
		return normalizeCountry(value)
	}
	for _, pair := range []string{"JP", "HK", "US", "TW", "SG", "DE", "GB", "KR"} {
		flag := string([]rune{rune(0x1f1e6) + rune(pair[0]-'A'), rune(0x1f1e6) + rune(pair[1]-'A')})
		if strings.Contains(name, flag) {
			return pair, nil
		}
	}
	upper := strings.ToUpper(name)
	words := strings.FieldsFunc(upper, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for i, word := range words {
		if country, ok := regions[word]; ok {
			return country, nil
		}
		if i+1 < len(words) {
			if country, ok := regions[word+words[i+1]]; ok {
				return country, nil
			}
		}
	}
	return "OTHER", nil
}

func normalizeCountry(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "OTHER" {
		return value, nil
	}
	if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
		return "", errors.New("country override must be a two-letter country code or OTHER")
	}
	return value, nil
}
