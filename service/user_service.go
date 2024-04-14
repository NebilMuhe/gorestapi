package service

import (
	"github.com/joho/godotenv"
	"gitlab.com/Nebil/errors"
)

func LoadEnv() error {
	err := godotenv.Load(".env")
	if err != nil {
		return errors.ErrUnableToLoad.Wrap(err, "unable to load")
	}
	return nil
}
