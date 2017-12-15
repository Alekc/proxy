package main

import "github.com/alekc/proxy/judge"

func main() {
	//port := flag.Int64("port",8080,"Listening port")
	pJudge := judge.Create()
	pJudge.DebugEnabled = true
	pJudge.Start()
}
