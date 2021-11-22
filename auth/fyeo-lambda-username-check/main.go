package main

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

var (
	AWS_REGION = "eu-north-1"

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

type UsernameCheck struct {
	Username string `json:"username"`
}

func main() {
	lambda.Start(Handler)
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

func UsernameAvailable(username string) error {
	_, err := Cognito.AdminGetUser(context.TODO(), &cognito.AdminGetUserInput{
		UserPoolId: aws.String(USER_POOL_ID),
		Username:   aws.String(username),
	})

	return err
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error
	check := UsernameCheck{}

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	err = json.Unmarshal([]byte(request.Body), &check)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	err = UsernameAvailable(check.Username)
	if err == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 409,
			Body:       "Username not available",
			Headers:    defaultHeaders,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    defaultHeaders,
		Body:       "OK",
	}, nil
}
