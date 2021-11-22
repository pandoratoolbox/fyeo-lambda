package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Strings []string

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
	ZendeskTicketID string    `json:"zendesk_ticket_id" bson:"zendesk_ticket_id"`
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
	ClosedDate      time.Time `json:"closed_date,omitempty" bson:"closed_date,omitempty"`
	ClassifiedDate  time.Time `json:"classified_date,omitempty" bson:"classifiedDate,omitempty"`
	Date            time.Time `json:"date,omitempty" bson:"date,omitempty"`
	Active          bool      `json:"active" bson:"active"`
	Reported        bool      `json:"reported" bson:"reported"`
	// Case              Case          `json:"case"`
	// Asset Asset json:"asset"
	AssetName string `json:"asset_name"`
	CaseName  string `json:"case_name"`
}

// type Event struct {
// 	ID          string `json:"id" bson:"_id"`
// 	CaseID      string `json:"caseId" bson:"caseId"`
// 	Url         string `json:"url" bson:"url"`
// 	Title       string `json:"title" bson:"title"`
// 	ContentHash string `json:"contentHash" bson:"contentHash"`
// }

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

	c_filter := bson.M{"group": bson.M{"$in": groups}, "status": bson.M{"$ne": "archived"}}
	res, err := MongoClient.Database("fyeo-di").Collection("cases").Find(ctx, c_filter)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	cases := make(map[string]Case)
	var case_ids []string
	for res.Next(ctx) {
		var doc Case

		err := res.Decode(&doc)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		cases[doc.ID] = doc
		case_ids = append(case_ids, doc.ID)
	}

	if len(cases) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No cases found with provided group permissions").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//filter2 := bson.M{"parentId": bson.M{"$in": case_ids}, "status": bson.M{"$ne": "archived"}}
	filter := map[string]interface{}{
		"parentId": map[string]interface{}{"$in": case_ids},
		"status":   map[string]interface{}{"$ne": "archived"},
	}

	q_cases, ok := request.QueryStringParameters["cases"]
	if ok {
		q_cases_arr := strings.Split(q_cases, ",")
		// var q_cases_ids []primitive.ObjectID
		// for _, cid := range q_cases_arr {
		// 	ccid, err := primitive.ObjectIDFromHex(cid)
		// 	if err != nil {
		// 		fmt.Println(err)
		// 		continue
		// 	}
		// q_cases_ids = append(q_cases_ids, ccid)
		// }

		if len(q_cases_arr) > 0 {
			var cases_arr []string
			for _, id := range q_cases_arr {
				_, ok := cases[id]
				if ok {
					cases_arr = append(cases_arr, id)
				}
			}
			filter["parentId"] = map[string]interface{}{
				"$in": cases_arr,
			}
		}

	}

	q_title, ok := request.QueryStringParameters["title"]
	if ok {
		filter["title"] = map[string]interface{}{
			"$regex":   ".*" + q_title + ".*",
			"$options": "i",
		}
	}

	q_severity, ok := request.QueryStringParameters["severity"]
	if ok {
		severity, err := strconv.ParseInt(q_severity, 10, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		filter["severity"] = map[string]interface{}{
			"$gte": severity,
		}
	}

	q_kind, ok := request.QueryStringParameters["type"]
	if ok {
		filter["type"] = map[string]interface{}{
			"$eq": q_kind,
		}
	}

	q_reported, ok := request.QueryStringParameters["reported"]
	if ok {
		reported, err := strconv.ParseBool(q_reported)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		filter["reported"] = map[string]interface{}{
			"$eq": reported,
		}
	}

	q_active, ok := request.QueryStringParameters["active"]
	if ok {
		active, err := strconv.ParseBool(q_active)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		filter["active"] = map[string]interface{}{
			"$eq": active,
		}
	}

	q_date_from, ok := request.QueryStringParameters["date_from"]
	if ok {
		date_from, err := strconv.ParseInt(q_date_from, 10, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		df_unix := time.Unix(date_from, 0)

		filter["date"] = map[string]interface{}{
			"$gte": df_unix,
		}
	}

	q_date_to, ok := request.QueryStringParameters["date_to"]
	if ok {
		date_to, err := strconv.ParseInt(q_date_to, 10, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		dt_unix := time.Unix(date_to, 0)

		_, ok := filter["date"]
		if ok {
			filter["date"].(map[string]interface{})["$lte"] = dt_unix
		}
		if !ok {
			filter["date"] = map[string]interface{}{
				"$lte": date_to,
			}
		}
	}

	js, err := json.Marshal(filter)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var b_filter interface{}

	err = bson.UnmarshalExtJSON(js, true, &b_filter)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	res, err = MongoClient.Database("fyeo-di").Collection("incidents").Find(ctx, filter) //, options.Find().SetLimit(100))

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//var data []Incident
	var data []map[string]interface{}
	for res.Next(ctx) {
		//var doc Incident
		doc := make(map[string]interface{})

		err := res.Decode(&doc)
		if err != nil {
			// return events.APIGatewayProxyResponse{
			// 	StatusCode: 400,
			// 	Body:       err.Error(),
			// 	Headers:    defaultHeaders,
			// }, nil
			continue
		}

		doc["group"] = cases[doc["parentId"].(string)].Group
		doc["case_name"] = cases[doc["parentId"].(string)].Name

		data = append(data, doc)
	}

	if len(data) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No incidents found for the case ID provided").Error(),
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
