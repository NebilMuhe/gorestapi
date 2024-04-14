package main

import (
	"log"

	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Println(err)
		return
	}
	defer logger.Sync()
}
