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
	res, err := MongoClient.Database("fyeo-di").Collection("cases").Find(ctx, filter)
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

	filter2 := bson.M{"case_id": bson.M{"$in": case_ids}, "status": bson.M{"$ne": "archived"}}

	q_kind, ok := request.QueryStringParameters["type"]
	if ok {
		filter2["asset_type"] = map[string]interface{}{
			"$eq": q_kind,
		}
	}

	q_threat_actor, ok := request.QueryStringParameters["threat_actor"]
	if ok {
		threat_actor, err := strconv.ParseBool(q_threat_actor)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		filter2["is_threat_actor"] = map[string]interface{}{
			"$eq": threat_actor,
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

		filter2["active"] = map[string]interface{}{
			"$eq": active,
		}
	}

	q_name, ok := request.QueryStringParameters["name"]
	if ok {
		filter2["name.common"] = map[string]interface{}{
			"$regex":   ".*" + q_name + ".*",
			"$options": "i",
		}
	}

	q_score_min, ok := request.QueryStringParameters["score_min"]
	if ok {
		score_min, err := strconv.ParseFloat(q_score_min, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		filter2["required_score"] = map[string]interface{}{
			"$gte": score_min,
		}
	}

	q_score_max, ok := request.QueryStringParameters["score_max"]
	if ok {
		score_max, err := strconv.ParseFloat(q_score_max, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		_, ok := filter["required_score"]
		if ok {
			filter2["required_score"].(map[string]interface{})["$lte"] = score_max
		}
		if !ok {
			filter2["required_score"] = map[string]interface{}{
				"$lte": score_max,
			}
		}
	}

	var incident_count_min int64
	q_incident_count_min, ok := request.QueryStringParameters["incident_count_min"]
	if ok {
		incident_count_min, err = strconv.ParseInt(q_incident_count_min, 10, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}
	}

	var incident_count_max int64
	q_incident_count_max, ok := request.QueryStringParameters["incident_count_max"]
	if ok {
		incident_count_max, err = strconv.ParseInt(q_incident_count_max, 10, 64)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}
	}

	res, err = MongoClient.Database("fyeo-di").Collection("assets").Find(ctx, filter2) //, options.Find().SetLimit(100))

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//var assets []Asset
	var assets []map[string]interface{}
	var asset_list []string
	for res.Next(ctx) {
		//var doc Asset
		doc := make(map[string]interface{})

		err := res.Decode(&doc)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		doc["group"] = cases[doc["case_id"].(string)].Group
		doc["case_name"] = cases[doc["case_id"].(string)].Name

		_, ok := doc["name"]
		if ok {
			_, ok := doc["name"].(map[string]interface{})["common"]
			if ok {
				_, ok := doc["name"].(map[string]interface{})["common"].(string)
				if ok {
					asset_list = append(asset_list, doc["name"].(map[string]interface{})["common"].(string))
				}
			}
		}
		assets = append(assets, doc)
	}

	if len(assets) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No assets found for the case ID provided").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	//get incidents for incident count

	filter3 := bson.M{"targets": bson.M{"$elemMatch": bson.M{"$in": asset_list}}}
	res3, err := MongoClient.Database("fyeo-di").Collection("incidents").Find(context.Background(), filter3)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	incident_count_map := make(map[string]int)
	//incidents := make(map[string]interface{})
	//var incidents []map[string]interface{}
	for res3.Next(context.Background()) {
		incident := make(map[string]interface{})
		err := res3.Decode(&incident)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}
		_, ok := incident["targets"]
		if ok {
			_, ok = incident["targets"].(bson.A)
			if ok {
				for _, target := range incident["targets"].(bson.A) {
					_, ok = target.(string)
					if ok {
						_, ok := incident_count_map[target.(string)]
						if ok {
							incident_count_map[target.(string)]++
							continue
						}
						incident_count_map[target.(string)] = 1
					}
				}
			}
		}

		//incidents = append(incidents, incident)

	}

	var zero_incidents bool
	if len(incident_count_map) < 1 {
		zero_incidents = true
	}

	//add incident_count to each document in assets
	var out []map[string]interface{}
	for i := range assets {
		if zero_incidents {
			assets[i]["incident_count"] = 0

		} else {
			if assets[i]["name"] != nil {
				_, ok := assets[i]["name"].(map[string]interface{})["common"]
				if ok {
					_, ok := assets[i]["name"].(map[string]interface{})["common"].(string)
					if ok {
						_, ok := incident_count_map[assets[i]["name"].(map[string]interface{})["common"].(string)]
						if ok {
							assets[i]["incident_count"] = incident_count_map[assets[i]["name"].(map[string]interface{})["common"].(string)]

						}
					}
				}
			}
		}

		_, ok = assets[i]["incident_count"]
		if !ok {
			assets[i]["incident_count"] = 0
		}

		if incident_count_max > 0 {
			if int64(assets[i]["incident_count"].(int)) > incident_count_max {
				continue
			}
		}

		if incident_count_min > 0 {
			if int64(assets[i]["incident_count"].(int)) < incident_count_min {
				continue
			}
		}

		out = append(out, assets[i])
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
