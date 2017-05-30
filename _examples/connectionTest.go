package main

import (
	"github.com/alekc/proxy/tester"
	"fmt"
)

func main() {
	test := tester.New()
	result, err := test.Check("91.185.189.219", 8080, tester.TYPE_HTTP)
	if err != nil {
		fmt.Sprintf("Error %+v", result)
		return
	}
	fmt.Sprintf("Result: %+v")
}
