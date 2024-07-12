package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	PrintMutex   = &sync.Mutex{}
	ColorsString = "0;31"
)

// Only run in locked thread
func AddLogs(entry domains.DomainLog, domainName string) {
	domainData := domains.DomainsData[domainName]
	domainData.LastLogs = append(domainData.LastLogs, entry)
	domains.DomainsData[domainName] = domainData
}

func FormatLogs(log domains.DomainLog) string {
	if log.BrowserFP != "" || log.BotFP != "" {
		return "[ " + PrimaryColor(log.Time) + " ] > \033[35m" + log.IP + "\033[0m - \033[32m" + log.BrowserFP + log.BotFP + "\033[0m - " + PrimaryColor(log.Useragent) + " - " + PrimaryColor(log.Path)
	}
	return "[ " + PrimaryColor(log.Time) + " ] > \033[35m" + log.IP + "\033[0m - \033[31mUNK (" + log.TLSFP + ")\033[0m - " + PrimaryColor(log.Useragent) + " - " + PrimaryColor(log.Path)
}

// Only run in locked thread
func ReadLogs(domainName string) {
	firewall.Mutex.RLock()
	domainData := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()

	//Calculate how close we are to overflowing
	logOverflow := len(domainData.LastLogs) - proxy.MaxLogLength

	if logOverflow > 0 {

		// Remove overflown element(s)
		domainData.LastLogs = domainData.LastLogs[logOverflow:]
		firewall.Mutex.Lock()
		domains.DomainsData[domainName] = domainData
		firewall.Mutex.Unlock()
	}

	for i, log := range domainData.LastLogs {
		// Check if out log is too big to display fully

		parsedOut := FormatLogs(log)

		if len(parsedOut)+4 > proxy.TWidth {
			fmt.Print("\033[" + fmt.Sprint(11+i) + ";1H\033[K[" + PrimaryColor("-") + "] " + parsedOut[:len(parsedOut)-(len(parsedOut)+4-proxy.TWidth)] + " ...\033[0m\n")
		} else {
			fmt.Print("\033[" + fmt.Sprint(11+i) + ";1H\033[K[" + PrimaryColor("-") + "] " + parsedOut + "\n")
		}
	}
	MoveInputLine()
}

// Only run in locked thread
func ClearLogs(domainName string) domains.DomainData {
	domainData := domains.DomainsData[domainName]
	domainData.LastLogs = nil
	domains.DomainsData[domainName] = domainData
	return domainData
}

func MoveInputLine() {
	fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + PrimaryColor("Command") + " ]: \033[u\033[s")
}

func PrimaryColor(input string) string {
	return "\033[" + ColorsString + "m" + input + "\033[0m"
}

func SetColor(colorMap []string) {
	res := ""
	for _, color := range colorMap {
		res += color + ";"
	}
	ColorsString = res[:len(res)-1]
}

func ClearScreen(length int) {
	fmt.Print("\033[s")
	for j := 1; j < 9+length; j++ {
		fmt.Println("\033[" + fmt.Sprint(j) + ";1H\033[K")
	}
}

func ReadTerminal() string {
	reader := bufio.NewScanner(os.Stdin)
	reader.Scan()
	return strings.ToLower(reader.Text())
}

func EvalYN(input string, defVal bool) (result bool) {
	switch input {
	case "y":
		return true
	case "yes":
		return true
	case "true":
		return true
	case "n":
		return false
	case "no":
		return false
	case "false":
		return false
	default:
		return defVal
	}
}

func AskBool(question string, defaultVal bool) bool {
	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + PrimaryColor("-") + "] [ " + PrimaryColor("Using Default Value "+fmt.Sprint(defaultVal)) + " ]")
		return defaultVal
	}
	return EvalYN(input, defaultVal)
}

func AskInt(question string, defaultVal int) int {
	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + PrimaryColor("-") + "] [ " + PrimaryColor("Using Default Value "+fmt.Sprint(defaultVal)) + " ]")
		return defaultVal
	}
	result, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("[" + PrimaryColor("!") + "] [ " + PrimaryColor("The Provided Answer Is Not A Number!") + " ]")
		return AskInt(question, defaultVal)
	}
	return result
}

func AskString(question string, defaultVal string) string {
	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + PrimaryColor("-") + "] [ " + PrimaryColor("Using Default Value "+defaultVal) + " ]")
		return defaultVal
	}
	return input
}

func JsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	// Trim the beginning and trailing " character
	return string(b[1 : len(b)-1])
}

func TrimTime(timestamp int) int {
	return (timestamp / 10) * 10
}

func SafeString(str string) string {
	return string([]byte(str))
}

func StageToString(stage int) string {
	switch stage {
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3"
	case 4:
		return "4"
	default:
		return "5+"
	}
}

func closestTo10(n int) int {
	if n == 0 {
		return 10
	}

	if n%10 >= 5 {
		return (n/10 + 1) * 10
	}

	result := n / 10 * 10

	if result == 0 {
		return 10
	}

	return result
}
