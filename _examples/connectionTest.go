package main

import (
	"fmt"
	"github.com/alekc/proxy/tester"
)

func main() {
	test := tester.New()
	//tester.CheckIfPortOpen("212.237.7.129", 80, time.Second*5)
	//result, err := test.Check("91.185.189.219", 8080, tester.TYPE_HTTP)
	result, err := test.Check("85.202.11.47", 3128, tester.TYPE_HTTP)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error %+v", result))
		return
	}
	fmt.Printf("Result: %+v", result)
}
