package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	// "go.mongodb.org/mongo-driver/mongo"
	// "go.mongodb.org/mongo-driver/mongo/options"
)

var (
	DATABASE_HOST = os.Getenv("MONGO_HOST")

	AWS_REGION = os.Getenv("AWS_REGION")
	VPC_ID     = "vpc-079cef3f2ebeca476"

	USER_POOL_ID      = "eu-north-1_jooLgo7fH"
	APP_CLIENT_ID     = "27g9om086g9jtj27sdontp91b0"
	APP_CLIENT_SECRET = "12ju7usophdf7eea1eg2cdrb8qfsbgotuh92nhr3hskii4gfcbid"

	Cognito        *cognito.Client
	defaultHeaders = map[string]string{
		"Content-Type":                 "application/json",
		"Access-Control-Allow-Headers": "*",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, OPTIONS, POST",
		"Allow":                        "GET, OPTIONS, POST",
	}
	// MongoClient *mongo.Client
)

func main() {
	lambda.Start(Handler)
}

type RegisterRequest struct {
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Email     *string `json:"email"`
	Username  *string `json:"username"`
	Password  *string `json:"password"`
}

type User struct {
	ID             string `json:"id"`
	AwsCognitoUUID string `json:"aws_cognito_uuid"`
}

func Init() error {
	var err error

	err = ReuseCognito()
	if err != nil {
		return err
	}

	// err = ReuseDatabaseConnection()
	// if err != nil {
	// 	return err
	// }

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

// func ReuseDatabaseConnection() error {
// 	if MongoClient != nil {
// 		return nil
// 	} else {
// 		var err error
// 		ctx := context.Background()
// 		MongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(DATABASE_HOST))
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

func computeSecretHash(clientSecret string, username string, clientId string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientId))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	//	context.callbackWaitsForEmptyEventLoop = false;
	var err error

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	data := RegisterRequest{}
	err = json.Unmarshal([]byte(request.Body), &data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	secretHash := computeSecretHash(APP_CLIENT_SECRET, *data.Username, APP_CLIENT_ID)

	// var user User
	signup := &cognito.SignUpInput{
		Username:   aws.String(*data.Username),
		Password:   aws.String(*data.Password),
		ClientId:   aws.String(APP_CLIENT_ID),
		SecretHash: aws.String(secretHash),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("name"), Value: aws.String(*data.FirstName + " " + *data.LastName)},
			{Name: aws.String("given_name"), Value: aws.String(*data.FirstName)},
			{Name: aws.String("family_name"), Value: aws.String(*data.LastName)},
			{Name: aws.String("email"), Value: aws.String(*data.Email)},
			{Name: aws.String("custom:role"), Value: aws.String("1")},
		},
	}

	out, err := Cognito.SignUp(context.TODO(), signup)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	// user = User{
	// 	AwsCognitoUUID: *out.UserSub,
	// }

	// res, err := MongoClient.Database("fyeo").Collection("users").InsertOne(ctx, user)
	// if err != nil {
	// 	return user, err
	// }

	// user.ID = res.InsertedID.(primitive.ObjectID).String()

	// return user, nil

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
