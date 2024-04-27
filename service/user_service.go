package service

import (
	"context"
	"os"

	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/helpers"
	"gitlab.com/Nebil/models"
	"gitlab.com/Nebil/utils"
	"go.uber.org/zap"
)

type UserService interface {
	RegisterUser(ctx context.Context, user models.User) (*models.User, error)
	LoginUser(ctx context.Context, user models.UserLogin) (map[string]string, error)
	RefreshToken(ctx context.Context, tokeString string) (map[string]string, error)
}

type userService struct {
	repo   data.UserRepository
	logger utils.Logger
}

func NewUserService(repo data.UserRepository, logger utils.Logger) UserService {
	return &userService{repo: repo, logger: logger}
}

// RegisterUser implements UserService.
func (u *userService) RegisterUser(ctx context.Context, user models.User) (*models.User, error) {
	err := user.Validate(ctx, u.logger)
	if err != nil {
		return nil, err
	}

	exist, err := u.repo.IsExists(ctx, &user)
	if exist {
		return nil, err
	}

	password, err := helpers.HashPassword(ctx, user.Password, u.logger)
	if err != nil {
		return nil, err
	}
	user.Password = password

	us, err := u.repo.Register(ctx, &user)
	if err != nil {
		return nil, err
	}
	return us, nil
}

// LoginUser implements UserService.
func (u *userService) LoginUser(ctx context.Context, user models.UserLogin) (map[string]string, error) {
	err := user.Validate(ctx, u.logger)
	if err != nil {
		return nil, err
	}

	loggedIn, err := u.repo.IsLoggedIn(ctx, user.Username)
	if loggedIn {
		return nil, err
	}

	usr, err := u.repo.Login(ctx, &user)
	if err != nil {
		return nil, err
	}

	err = helpers.CheckPassword(ctx, usr.Password, user.Password, u.logger)
	if err != nil {
		return nil, err
	}

	token, err := helpers.CreateToken(ctx, usr.ID, usr.Username, u.logger)
	if err != nil {
		return nil, err
	}

	refreshToken := token["refresh_token"]
	key := os.Getenv("ENCRYPTION_KEY")
	encryptedToken, err := helpers.Encrypt(ctx, []byte(key), refreshToken, u.logger)
	if err != nil {
		return nil, err
	}
	_, err = u.repo.Refresh(ctx, usr.Username, encryptedToken)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// RefreshToken implements UserService.
func (u *userService) RefreshToken(ctx context.Context, tokeString string) (map[string]string, error) {
	err := helpers.VerifyToken(ctx, tokeString, u.logger)
	if err != nil {
		return nil, err
	}

	value, err := helpers.ExtractUsernameAndID(ctx, tokeString, u.logger)
	if err != nil {
		return nil, err
	}

	// userID := value["id"]
	contx := context.WithValue(ctx, "userID", value["id"])
	rfToken, err := u.repo.CheckToken(contx, value["username"])
	if err != nil {
		return nil, err
	}

	key := os.Getenv("ENCRYPTION_KEY")
	decryptRefToken, err := helpers.Decrypt(ctx, []byte(key), rfToken, u.logger)

	if err != nil {
		return nil, err
	}

	if decryptRefToken != tokeString {
		err = errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid token provided"), "invalid token")
		u.logger.Error(ctx, "invalid token", zap.Error(err))
		return nil, err
	}

	token, err := helpers.CreateToken(ctx, value["id"], value["username"], u.logger)
	if err != nil {
		return nil, err
	}

	refreshToken := token["refresh_token"]
	encryptedToken, err := helpers.Encrypt(ctx, []byte(key), refreshToken, u.logger)
	if err != nil {
		return nil, err
	}

	_, err = u.repo.UpdateToken(ctx, encryptedToken, value["username"])
	if err != nil {
		return nil, err
	}

	return token, nil
}
