package main

import (
	"context"
	"errors"
	"strings"
	"time"

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

type Strings []string

type Incident struct {
	S3Link          *string    `json:"s3_link" bson:"s3_link"`
	ZendeskTicketID *int64     `json:"zendesk_ticket_id" bson:"zendesk_ticket_id"`
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

	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter := bson.M{"_id": o_id}

	err = Init()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

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

	//we can store the incident ID as an external_id in the zendesk ticket so it's possible to query the zendesk API without querying the database first
	data := zendesk.Ticket{
		ExternalID: &id,
		//need to decide data to send to tickets
	}

	err = json.Unmarshal([]byte(request.Body), &data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	ticket, err := ZendeskClient.CreateTicket(&data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	update := bson.M{"$set": bson.M{"zendesk_ticket_id": *ticket.ID}}

	filter2 := bson.M{"_id": o_id}
	res2, err := MongoClient.Database("fyeo-di").Collection("incidents").UpdateOne(context.Background(), filter2, update)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	if res2.UpsertedID == nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("Unable to update incident").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	out.ZendeskTicketID = ticket.ID

	js, err := json.Marshal(ticket)
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
