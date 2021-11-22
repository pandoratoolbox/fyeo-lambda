package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognitoidentity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	Cfg aws.Config
)

func ReuseCognitoIdentity() error {
	if CognitoID != nil {
		return nil
	} else {
		var err error
		Cfg, err = config.LoadDefaultConfig(context.TODO())
		CognitoID = cognitoidentity.NewFromConfig(Cfg)
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

	claims := request.RequestContext.Authorizer["claims"]
	if claims == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No claims found for " + request.RequestContext.Identity.CognitoIdentityID).Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	rg := claims.(map[string]interface{})["cognito:groups"]

	if rg == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No group permissions set").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	groups := strings.Split(rg.(string), ",")

	// tok := request.Headers["Authorization"]

	// id_token := strings.TrimPrefix(tok, "Bearer ")

	// input := struct {
	// 	IdentityId string `json:"identity_id"`
	// }{}

	// err = json.Unmarshal([]byte(request.Body), &input)
	// if err != nil {
	// 	return events.APIGatewayProxyResponse{
	// 		StatusCode: 400,
	// 		Body:       err.Error(),
	// 		Headers:    defaultHeaders,
	// 	}, nil
	// }

	//IdentityId format - eu-north-1:username - might not need
	//id_id := "eu-north-1:" + request.RequestContext.Authorizer["username"].(string)

	principal_map := make(map[string]string)
	username, ok := claims.(map[string]interface{})["cognito:username"].(string)
	if !ok {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Unable to find username",
			Headers:    defaultHeaders,
		}, nil
	}
	for _, g := range groups {
		principal_map[g] = g
	}

	ident, err := CognitoID.GetOpenIdTokenForDeveloperIdentity(context.Background(), &cognitoidentity.GetOpenIdTokenForDeveloperIdentityInput{
		IdentityPoolId: aws.String(IDENTITY_POOL_ID),
		Logins: map[string]string{
			"login.fyeo.di": username,
		},
		PrincipalTags: principal_map,
	})

	// out, err := CognitoID.GetCredentialsForIdentity(context.Background(), &cognitoidentity.GetCredentialsForIdentityInput{
	// 	IdentityId: aws.String(input.IdentityId),
	// 	Logins: map[string]string{
	// 		"cognito-idp.eu-north-1.amazonaws.com/eu-north-1_jooLgo7fH": id_token,
	// 	},
	// })
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	Sts := sts.NewFromConfig(Cfg)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	out, err := Sts.AssumeRoleWithWebIdentity(context.Background(), &sts.AssumeRoleWithWebIdentityInput{
		WebIdentityToken: aws.String(*ident.Token),
		RoleArn:          aws.String("arn:aws:iam::340856162020:role/fyeo-di-identity-auth"),
		RoleSessionName:  aws.String(username),
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
