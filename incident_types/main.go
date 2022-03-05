package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Strings []string

type IncidentType struct {
	ID             *string `json:"id,omitempty" bson:"_id,omitempty"`
	Severity       *int64  `json:"severity,omitempty" bson:"severity,omitempty"`
	Title          *string `json:"title,omitempty" bson:"title,omitempty"`
	Recommendation *string `json:"recommendation,omitempty" bson:"recommendation,omitempty"`
	BusinessImpact *string `json:"business_impact,omitempty" bson:"business_impact,omitempty"`
	Class          *string `json:"class,omitempty" bson:"class,omitempty"`
	Description    *string `json:"description,omitempty" bson:"description,omitempty"`
}

var (
	MongoClient *mongo.Client

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

func Init() error {
	var err error

	err = ReuseMongo()
	if err != nil {
		return err
	}

	return err
}

func UrlEncoded(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func ReuseMongo() error {

	if MongoClient != nil {
		return nil
	} else {
		var err error
		username := "stage"
		password := "GK!2f&Wf#z&RS3"

		password, err = UrlEncoded(password)
		if err != nil {
			return err
		}

		ctx := context.Background()

		MongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s@192.168.0.17:27017/?authSource=admin&ssl=false", username, password)))
		if err != nil {
			return err
		}
	}

	return nil
}

type ErrorResponse struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func ServeError(message string, code int) events.APIGatewayProxyResponse {
	js, _ := json.Marshal(ErrorResponse{
		Code:    code,
		Message: message,
	})

	return events.APIGatewayProxyResponse{
		StatusCode: code,
		Body:       string(js),
		Headers:    defaultHeaders,
	}
}

func Handler(rctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error

	err = Init()
	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	res, err := MongoClient.Database("fyeo-di").Collection("incident_types").Find(context.Background(), bson.D{})
	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	var data []IncidentType
	for res.Next(context.Background()) {
		var doc IncidentType

		err := res.Decode(&doc)
		if err != nil {
			return ServeError(err.Error(), 400), nil
		}

		data = append(data, doc)
	}

	js, err := json.Marshal(data)
	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(js),
		StatusCode: 200,
		Headers:    defaultHeaders,
	}, nil
}
