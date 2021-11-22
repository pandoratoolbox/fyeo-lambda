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

type Case struct {
	ID       string `json:"id" bson:"_id"`
	Name     string `json:"name" bson:"caseName"`
	CaseType string `json:"case_type" bson:"caseType"`
	Email    string `json:"email" bson:"caseEmail"`
	Type     string `json:"type" bson:"type"`
	Group    string `json:"group" bson:"group"`
}

type Strings []string

type Incident struct {
	//ZendeskTicketID string    `json:"zendesk_ticket_id" bson:"zendesk_ticket_id"`
	ID              *string    `json:"id" bson:"_id"`
	Source          *string    `json:"source" bson:"source"`
	Title           *string    `json:"title" bson:"title"`
	Class           *string    `json:"class" bson:"class"`
	ClassifiedBy    *string    `json:"classified_by" bson:"classified_by"`
	Severity        *int64     `json:"severity" bson:"severity"`
	AssetID         *string    `json:"asset_id" bson:"asset_id"`
	CaseID          *string    `json:"case_id" bson:"parentId"`
	Events          *Strings   `json:"events" bson:"events"` //array of event IDs
	Description     *string    `json:"description" bson:"description"`
	Recommendations *string    `json:"recommendations" bson:"recommendations"`
	ThreatActorName *string    `json:"threat_actor_name" bson:"threat_actor_name"`
	ThreatActorId   *string    `json:"thread_actor_id" bson:"threat_actor_id"`
	Targets         *Strings   `json:"targets" bson:"targets"`
	Group           *string    `json:"group" bson:"group"`
	ReportedDate    *time.Time `json:"reported_date" bson:"reported_date"`
	ClosedDate      *time.Time `json:"closed_date" bson:"closed_date"`
	ClassifiedDate  *time.Time `json:"classified_date" bson:"classifiedDate"`
	UpdatedDate     *time.Time `json:"updated_date" bson:"updated_date"`
	Date            *time.Time `json:"date" bson:"date"`
	Active          *bool      `json:"active" bson:"active"`
	Reported        *bool      `json:"reported" bson:"reported"`
	Agent           *string    `json:"agent" bson:"agent"`
	// Case              Case          `json:"case"`
	// Asset Asset json:"asset"
	AssetName *string `json:"asset_name"`
	CaseName  *string `json:"case_name"`
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

	res := MongoClient.Database("fyeo-di").Collection("incidents").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error() + " for " + o_id.String(),
			Headers:    defaultHeaders,
		}, nil
	}

	var out Incident

	err = res.Decode(&out)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//check case for groups

	c_id, err := primitive.ObjectIDFromHex(*out.CaseID)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter = bson.M{"_id": c_id, "group": bson.M{"$in": groups}}
	res2 := MongoClient.Database("fyeo-di").Collection("cases").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error() + ": " + *out.CaseID,
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

	out.Group = &ca.Group
	out.CaseName = &ca.Name

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
