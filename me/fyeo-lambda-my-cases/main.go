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
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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
	// Case              Case          `json:"case"`
	CaseName string `json:"case_name"`
}

type Case struct {
	ID       string `json:"id" bson:"_id"`
	Name     string `json:"name" bson:"caseName"`
	CaseType string `json:"case_type" bson:"caseType"`
	Email    string `json:"email" bson:"caseEmail"`
	Type     string `json:"type" bson:"type"`
	Group    string `json:"group" bson:"group"`
}

type Incident struct {
	//ZendeskTicketID string    `json:"zendesk_ticket_id" bson:"zendesk_ticket_id"`
	ID              string    `json:"id" bson:"_id"`
	Source          string    `json:"source" bson:"source"`
	Title           string    `json:"title" bson:"title"`
	Type            string    `json:"type" bson:"type"`
	Severity        int64     `json:"severity" bson:"severity"`
	AssetID         string    `json:"asset_id" bson:"asset_id"`
	CaseID          string    `json:"case_id" bson:"parentId"`
	Events          []string  `json:"events" bson:"events"` //array of event IDs
	Description     string    `json:"description" bson:"description"`
	Recommendations string    `json:"recommendations" bson:"recommendations"`
	Targets         []string  `json:"targets" bson:"targets"`
	Group           string    `json:"group" bson:"group"`
	ReportedDate    time.Time `json:"reported_date" bson:"reported_date"`
	ClosedDate      time.Time `json:"closed_date" bson:"closed_date"`
	ClassifiedDate  time.Time `json:"classified_date" bson:"classified_date"`
	Date            time.Time `json:"date" bson:"date"`
	Active          bool      `json:"active" bson:"active"`
	Reported        bool      `json:"reported" bson:"reported"`
	// Case              Case          `json:"case"`
	// Asset Asset json:"asset"
	AssetName string `json:"asset_name"`
	CaseName  string `json:"case_name"`
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

	filter := bson.M{"group": bson.M{"$in": groups}, "status": bson.M{"$ne": "archived"}}
	res, err := MongoClient.Database("fyeo-di").Collection("cases").Find(ctx, filter) //options.Find().SetLimit(100))
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//var cases []Case
	var cases []map[string]interface{}
	for res.Next(ctx) {
		//var doc Case
		var doc map[string]interface{}

		err := res.Decode(&doc)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		cases = append(cases, doc)
	}

	if len(cases) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No cases found with provided group permissions").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	js, err := json.Marshal(cases)
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
