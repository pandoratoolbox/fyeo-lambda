package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Strings []string

type IncidentType struct {
	ID             *string `json:"id" bson:"_id"`
	Description    *string `json:"description" bson:"description"`
	Class          *string `json:"class" bson:"class"`
	Severity       *int64  `json:"severity" bson:"severity"`
	BusinessImpact *string `json:"business_impact" bson:"business_impact"`
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

func ReuseMongo() error {
	if MongoClient != nil {
		return nil
	} else {
		var err error
		ctx := context.Background()

		uri := "mongodb://192.168.0.229:27017"

		MongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
		if err != nil {
			return err
		}
	}

	return nil
}

func Handler(rctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	res, err := MongoClient.Database("fyeo-di").Collection("incident_descriptions").Find(ctx, bson.D{})
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var data []IncidentType
	for res.Next(ctx) {
		var doc IncidentType

		err := res.Decode(&doc)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		data = append(data, doc)
	}

	if len(data) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No incident_types found").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	out, err := json.Marshal(data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(out),
		StatusCode: 200,
		Headers:    defaultHeaders,
	}, nil
}
