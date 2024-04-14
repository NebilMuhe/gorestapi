package main

import (
	"log"

	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Println(err)
		return
	}
	defer logger.Sync()

	err = service.LoadEnv()
	if err != nil {
		log.Println(err)
		return
	}
}
