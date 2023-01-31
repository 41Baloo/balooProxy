package utils

import (
	"bufio"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/proxy"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	PrintMutex = &sync.Mutex{}
)

func AddLogs(entry string, domain domains.DomainSettings) domains.DomainSettings {

	PrintMutex.Lock()
	if len(domain.LastLogs) > proxy.MaxLogLength {
		domain.LastLogs = domain.LastLogs[1:]
		domain.LastLogs = append(domain.LastLogs, entry)

		for i, log := range domain.LastLogs {
			if len(log)+4 > proxy.TWidth {
				fmt.Print("\033[" + fmt.Sprint(11+i) + ";1H\033[K[" + RedText("!") + "] " + log[:len(log)-(len(log)+4-proxy.TWidth)] + " ...\033[0m\n")
			} else {
				fmt.Print("\033[" + fmt.Sprint(11+i) + ";1H\033[K[" + RedText("!") + "] " + log + "\n")
			}
		}
		MoveInputLine()
		PrintMutex.Unlock()
		return domain
	}
	domain.LastLogs = append(domain.LastLogs, entry)
	if domain.Name == proxy.WatchedDomain {
		if len(entry)+4 > proxy.TWidth {
			fmt.Print("\033[" + fmt.Sprint((10 + len(domain.LastLogs))) + ";1H\033[K[" + RedText("-") + "] " + entry[:len(entry)-(len(entry)+4-proxy.TWidth)] + " ...\033[0m\n")
		} else {
			fmt.Print("\033[" + fmt.Sprint((10 + len(domain.LastLogs))) + ";1H\033[K[" + RedText("-") + "] " + entry + "\n")
		}
	}
	MoveInputLine()
	PrintMutex.Unlock()
	return domain
}

func MoveInputLine() {
	fmt.Println("\033[" + fmt.Sprint(12+10) + ";1H")
	fmt.Print("[ " + RedText("Command") + " ]: \033[u\033[s")
}

func RedText(input string) string {
	return "\033[31m" + input + "\033[0m"
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
	fmt.Print("[" + RedText("+") + "] [ " + RedText(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + RedText("-") + "] [ " + RedText("Using Default Value "+fmt.Sprint(defaultVal)) + " ]")
		return defaultVal
	}
	return EvalYN(input, defaultVal)
}

func AskInt(question string, defaultVal int) int {
	fmt.Print("[" + RedText("+") + "] [ " + RedText(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + RedText("-") + "] [ " + RedText("Using Default Value "+fmt.Sprint(defaultVal)) + " ]")
		return defaultVal
	}
	result, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("[" + RedText("!") + "] [ " + RedText("The Provided Answer Is Not A Number!") + " ]")
		return AskInt(question, defaultVal)
	}
	return result
}

func AskString(question string, defaultVal string) string {
	fmt.Print("[" + RedText("+") + "] [ " + RedText(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + RedText("-") + "] [ " + RedText("Using Default Value "+defaultVal) + " ]")
		return defaultVal
	}
	return input
}
