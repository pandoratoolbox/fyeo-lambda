package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	Case              Case          `json:"case"`
	CaseName          string        `json:"case_name"`
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
	ReportedDate    time.Time `json:"reported_date,omitempty" bson:"reported_date,omitempty"`
	//ClosedDate      time.Time `json:"closed_date" bson:"closed_date"`
	ClassifiedDate time.Time `json:"classified_date,omitempty" bson:"classifiedDate,omitempty"`
	Date           time.Time `json:"date,omitempty" bson:"date,omitempty"`
	Active         bool      `json:"active" bson:"active"`
	Reported       bool      `json:"reported" bson:"reported"`
	// Case              Case          `json:"case"`
	// Asset Asset json:"asset"
	AssetName string `json:"asset_name"`
	CaseName  string `json:"case_name"`
}

var (
	Cognito     *cognito.Client
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

	err = ReuseCognito()
	if err != nil {
		return err
	}

	err = ReuseMongo()
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

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
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

	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter := bson.M{"_id": o_id}

	res := MongoClient.Database("fyeo-di").Collection("assets").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error() + " for " + o_id.String(),
			Headers:    defaultHeaders,
		}, nil
	}

	var out map[string]interface{}

	err = res.Decode(&out)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//check case for groups

	c_id, err := primitive.ObjectIDFromHex(out["case_id"].(string))
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter2 := bson.M{"_id": c_id, "group": bson.M{"$in": groups}}
	res2 := MongoClient.Database("fyeo-di").Collection("cases").FindOne(context.Background(), filter2)

	if res.Err() != nil {
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

	var asset_name string
	_, ok := out["name"]
	if ok {
		_, ok := out["name"].(map[string]interface{})
		if ok {
			_, ok := out["name"].(map[string]interface{})["common"]
			if ok {
				_, ok := out["name"].(map[string]interface{})["common"].(string)
				if ok {
					asset_name = out["name"].(map[string]interface{})["common"].(string)
				}
			}
		}
	}

	filter3 := bson.M{"targets": bson.M{"$elemMatch": bson.M{"$eq": asset_name}}}
	res3, err := MongoClient.Database("fyeo-di").Collection("incidents").Find(context.Background(), filter3, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var i_count int64
	var incidents []string
	for res3.Next(context.Background()) {
		doc := make(map[string]interface{})
		res3.Decode(&doc)
		incidents = append(incidents, doc["_id"].(primitive.ObjectID).Hex())
		i_count++
	}

	out["case_name"] = ca.Name
	out["group"] = ca.Group
	out["incidents"] = incidents
	out["incident_count"] = i_count

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
