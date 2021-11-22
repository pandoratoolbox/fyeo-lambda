package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/MEDIGO/go-zendesk/zendesk"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	ZENDESK_GROUP_ID     = 360001894394 //Support
	ZENDESK_SUBMITTER_ID = 384922910458 //support@gofyeo.com
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

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error

	var out map[string]interface{}

	err = json.Unmarshal([]byte(request.Body), &out)
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
	gMap := make(map[string]bool)
	for _, g := range groups {
		gMap[g] = true
	}

	_, ok := out["group"]
	if ok {
		og, ok := out["group"].(string)
		if !ok {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       errors.New("Unable to convert input group value to string").Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		_, ok = gMap[og]
		if !ok {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       errors.New("You do not have permissions for this group").Error(),
				Headers:    defaultHeaders,
			}, nil
		}

	}

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var data interface{}

	err = bson.UnmarshalExtJSON([]byte(request.Body), true, &data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	insert := data.(bson.D)

	res, err := MongoClient.Database("fyeo-di").Collection("incidents").InsertOne(context.Background(), insert)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	if res.InsertedID == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("Unable to insert object").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	out["_id"] = res.InsertedID.(primitive.ObjectID).Hex()

	if int(out["severity"].(float64)) >= 2 {
		//https://developer.zendesk.com/api-reference/ticketing/ticket-management/search/#query-basics
		//we need to search organizations by domains and save organization ids in a new collection
		//or list organizations and check for ones which contain the specified domain from the associated case record
		//then look for users in organization and select one as requester
		//need to start the pipeline from scratch and make sure we are saving cases with zendesk organisation IDs from the beginning
		//what are we going to use to search for organizations automatically to get these IDs? It will be inaccurate with discrepancies if we don't implement zendesk_organization_id field from the start and try to guess later
		ext_id := out["_id"].(string)
		grp_id := int64(ZENDESK_GROUP_ID)
		rq_id := int64(1) // get zendesk_id from case
		sb_id := int64(ZENDESK_SUBMITTER_ID)
		priority := "high"
		tp := "incident"
		st := "open"
		//create zendesk ticket with ticket.external_id = out["_id"].Hex()
		ticket, err := ZendeskClient.CreateTicket(&zendesk.Ticket{
			RequesterID: &rq_id,
			GroupID:     &grp_id,
			ExternalID:  &ext_id,
			SubmitterID: &sb_id,
			Priority:    &priority,
			Type:        &tp,
			Status:      &st,
		})
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

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
