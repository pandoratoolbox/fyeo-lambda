package main

import (
	"context"
	"errors"

	"encoding/json"

	"github.com/MEDIGO/go-zendesk/zendesk"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	ZENDESK_GROUP_ID = 360001894394 //Support
)

var (
	MongoClient   *mongo.Client
	ZendeskClient zendesk.Client

	defaultHeaders = map[string]string{
		"Content-Type":                 "application/json",
		"Access-Control-Allow-Headers": "*",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, OPTIONS, POST",
		"Allow":                        "GET, OPTIONS, POST",
	}
)

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

func ReuseZendesk() error {
	var err error
	ZendeskClient, err = zendesk.NewClient("", "", "")
	if err != nil {
		return err
	}
	return nil
}

func main() {
	lambda.Start(Handler)
}

func Init() error {
	var err error

	err = ReuseMongo()
	if err != nil {
		return err
	}

	err = ReuseZendesk()
	if err != nil {
		return err
	}

	return err
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

	input := struct {
		IncidentID string `json:"incident_id"`
	}{}

	err = json.Unmarshal([]byte(request.Body), &input)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}
	//need to add auth for webhooks e.g API secret key
	//update incident in mongodb to 'closed'/'archived' status

	o_id, err := primitive.ObjectIDFromHex(input.IncidentID)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	update := bson.M{"$set": bson.M{"status": "archived"}}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("incidents").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	if res.UpsertedID == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("Unable to update object").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       "OK",
		StatusCode: 200,
		Headers:    defaultHeaders,
	}, nil
}
