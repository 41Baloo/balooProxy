package firewall

import (
	"fmt"
	"goProxy/core/domains"

	"github.com/kor44/gofilter"
)

func EvalFirewallRule(currDomain domains.DomainSettings, variables gofilter.Message, susLv int) int {
	result := susLv
	for index, rule := range currDomain.CustomRules {
		if rule.Filter.Apply(variables) {
			//Check if we want to statically set susLv or add to it
			switch rule.Action[:1] {
			case "+":
				var actionInt int
				_, err := fmt.Sscan(rule.Action[1:], &actionInt)
				if err != nil {
					fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
					//Dont change anything on error. We dont want issues in production
				} else {
					result = result + actionInt
					//fmt.Println("[" + PrimaryColor("+") + "] [ Matched Rule ] > " + fmt.Sprint(result))
				}
			case "-":
				var actionInt int
				_, err := fmt.Sscan(rule.Action[1:], &actionInt)
				if err != nil {
					fmt.Println("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
					//Dont change anything on error. We dont want issues in production
				} else {
					result = result - actionInt
					//fmt.Println("[" + PrimaryColor("+") + "] [ Matched Rule ] > " + fmt.Sprint(result))
				}
			default:
				var actionInt int
				_, err := fmt.Sscan(rule.Action, &actionInt)
				if err != nil {
					fmt.Printf("[ ! ] [ Error Evaluating Rule %d : %s ]\n", index, err.Error())
				} else {
					result = actionInt
					return result
				}
			}
		}
	}
	return result
}
