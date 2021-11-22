package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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

type Case struct {
	ID        string `json:"id" bson:"_id"`
	CaseName  string `json:"caseName" bson:"caseName"`
	CaseType  string `json:"caseType" bson:"caseType"`
	CaseEmail string `json:"caseEmail" bson:"caseEmail"`
	Type      string `json:"type" bson:"type"`
	Group     string `json:"group" bson:"group"`
}

type Asset struct {
	ID   string `json:"id" bson:"_id"`
	Name struct {
		Common string `json:"common" bson:"common"`
	} `json:"name" bson:"name"`
	AssetCreationDate time.Time     `json:"asset_creation_date" bson:"asset_creation_date"`
	AssetType         string        `json:"asset_type" bson:"asset_type"`
	CaseID            string        `json:"case_id" bson:"case_id"`
	Urls              []interface{} `json:"urls" bson:"urls"`
	Group             string        `json:"group"`
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

	id := request.PathParameters["id"]
	if id == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No ID provided").Error(),
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
	gMap := make(map[string]bool)
	for _, g := range groups {
		gMap[g] = true
	}

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	c_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter2 := bson.M{"_id": c_id, "group": bson.M{"$in": groups}, "status": bson.M{"$ne": "archived"}}
	res2 := MongoClient.Database("fyeo-di").Collection("cases").FindOne(context.Background(), filter2)

	if res2.Err() != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var ca Case

	err = res2.Decode(&ca)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter := bson.M{"case_id": id}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()

	res, err := MongoClient.Database("fyeo-di").Collection("assets").Find(ctx, filter)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var out []Asset
	for res.Next(ctx) {
		var doc Asset

		err := res.Decode(&doc)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		out = append(out, doc)
	}

	if len(out) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No assets found for the case ID provided").Error(),
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
