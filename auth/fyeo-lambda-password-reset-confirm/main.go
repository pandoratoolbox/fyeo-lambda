package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

var (
	AWS_REGION        = os.Getenv("AWS_REGION")
	USER_POOL_ID      = "eu-north-1_jooLgo7fH"
	APP_CLIENT_ID     = "27g9om086g9jtj27sdontp91b0"
	APP_CLIENT_SECRET = "12ju7usophdf7eea1eg2cdrb8qfsbgotuh92nhr3hskii4gfcbid"

	Cognito *cognito.Client

	defaultHeaders = map[string]string{
		"Content-Type":                 "application/json",
		"Access-Control-Allow-Headers": "*",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, OPTIONS, POST",
		"Allow":                        "GET, OPTIONS, POST",
	}
)

func main() {
	lambda.Start(Handler)
}

type Request struct {
	Username    string `json:"username"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"` //new password
}

func Init() error {
	var err error

	err = ReuseCognito()
	if err != nil {
		return err
	}

	return err
}

func ReuseCognito() error {
	if Cognito != nil {
		return nil
	} else {
		var err error
		cfg, err := config.LoadDefaultConfig(context.TODO())
		Cognito = cognito.NewFromConfig(cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

func computeSecretHash(clientSecret string, username string, clientId string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientId))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	data := Request{}
	err = json.Unmarshal([]byte(request.Body), &data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	secretHash := computeSecretHash(APP_CLIENT_SECRET, data.Username, APP_CLIENT_ID)

	out, err := Cognito.ConfirmForgotPassword(context.TODO(), &cognito.ConfirmForgotPasswordInput{
		ClientId:         aws.String(APP_CLIENT_ID),
		ConfirmationCode: aws.String(data.Code),
		SecretHash:       aws.String(secretHash),
		Password:         aws.String(data.NewPassword),
		Username:         aws.String(data.Username),
	})
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error() + fmt.Sprintln(data),
			Headers:    defaultHeaders,
		}, nil
	}

	js, err := json.Marshal(out)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(js),
		StatusCode: 200,
		Headers:    defaultHeaders,
	}, nil
}
