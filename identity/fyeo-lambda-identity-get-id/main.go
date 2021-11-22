package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognitoidentity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
)

var (
	AWS_REGION        = os.Getenv("AWS_REGION")
	USER_POOL_ID      = "eu-north-1_jooLgo7fH"
	APP_CLIENT_ID     = "27g9om086g9jtj27sdontp91b0"
	APP_CLIENT_SECRET = "12ju7usophdf7eea1eg2cdrb8qfsbgotuh92nhr3hskii4gfcbid"
	IDENTITY_POOL_ID  = "eu-north-1:1b10f408-50a9-4204-9194-c143fdb03278"

	CognitoID *cognitoidentity.Client

	defaultHeaders = map[string]string{
		"Content-Type":                 "application/json",
		"Access-Control-Allow-Headers": "*",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, OPTIONS, POST",
		"Allow":                        "GET, OPTIONS, POST",
	}
)

func ReuseCognitoIdentity() error {
	if CognitoID != nil {
		return nil
	} else {
		var err error
		cfg, err := config.LoadDefaultConfig(context.TODO())
		CognitoID = cognitoidentity.NewFromConfig(cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

func Init() error {
	var err error
	err = ReuseCognitoIdentity()
	if err != nil {
		return err
	}

	return nil
}

func main() {
	lambda.Start(Handler)
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

	tok := request.Headers["Authorization"]

	id_token := strings.TrimPrefix(tok, "Bearer ")

	out, err := CognitoID.GetId(context.Background(), &cognitoidentity.GetIdInput{
		IdentityPoolId: aws.String(IDENTITY_POOL_ID),
		Logins: map[string]string{
			"cognito-idp.eu-north-1.amazonaws.com/eu-north-1_jooLgo7fH": id_token,
		},
	})
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
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
		StatusCode: 200,
		Body:       string(js),
		Headers:    defaultHeaders,
	}, nil
}
