package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.mongodb.org/mongo-driver/bson"
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

type Strings []string

type AssetNetloc struct {
	Cidr     *string `json:"cidr,omitempty" bson:"cidr,omitempty"`
	AsNumber *string `json:"as_number,omitempty" bson:"as_number,omitempty"`
}

type AssetWhois struct {
	Domain      *string    `json:"domain,omitempty" bson:"domain,omitempty"`
	Created     *time.Time `json:"created,omitempty" bson:"created,omitempty"`
	Updated     *time.Time `json:"updated,omitempty" bson:"updated,omitempty"`
	Expires     *time.Time `json:"expires,omitempty" bson:"expires,omitempty"`
	Registrar   *string    `json:"registrar,omitempty" bson:"registrar,omitempty"`
	Registrant  *string    `json:"registrant,omitempty" bson:"registrant,omitempty"`
	Nameservers *Strings   `json:"nameservers,omitempty" bson:"names_servers,omitempty"`
	Status      *string    `json:"status,omitempty" bson:"status,omitempty"`
}

type AssetLocation struct {
	StreetNumber *int64   `json:"street_number,omitempty" bson:"street_number,omitempty"`
	PostalTown   *string  `json:"postal_town,omitempty" bson:"postal_town,omitempty"`
	Country      *string  `json:"country,omitempty" bson:"country,omitempty"`
	StreetName   *string  `json:"street_name,omitempty" bson:"street_name,omitempty"`
	Premise      *string  `json:"premise,omitempty" bson:"premise,omitempty"`
	Lat          *float64 `json:"lat,omitempty" bson:"lat,omitempty"`
	Lng          *float64 `json:"lng,omitempty" bson:"lng,omitempty"`
}

type AssetName struct {
	Common *string `json:"common,omitempty" bson:"common,omitempty"`
	First  *string `json:"first,omitempty" bson:"first,omitempty"`
	Last   *string `json:"last,omitempty" bson:"last,omitempty"`
	Middle *string `json:"middle,omitempty" bson:"middle,omitempty"`
	Nick   *string `json:"nick,omitempty" bson:"nick,omitempty"`
}

type AssetOrganization struct {
	Role *string `json:"role,omitempty" bson:"role,omitempty"`
	Name *string `json:"name,omitempty" bson:"name,omitempty"`
}

type Asset struct {
	ID                *string      `json:"id,omitempty" bson:"_id,omitempty"`
	CaseID            *string      `json:"case_id,omitempty" bson:"case_id,omitempty"`
	SocialMedia       []*TagPair   `json:"social_media,omitempty" bson:"social_media,omitempty"`
	IPs               *Strings     `json:"ips,omitempty" bson:"ips,omitempty"`
	Name              *AssetName   `json:"name,omitempty" bson:"name,omitempty"`
	Netloc            *AssetNetloc `json:"netloc,omitempty" bson:"netloc,omitempty"`
	AssetCreationDate *time.Time   `json:"asset_creation_date,omitempty" bson:"asset_creation_date,omitempty"`
	LastDumpSearch    *time.Time   `json:"last_dump_search,omitempty" bson:"last_dump_search,omitempty"`
	LastSimilarSearch *time.Time   `json:"last_similar_search,omitempty" bson:"last_similar_search,omitempty"`
	LastUpdated       *time.Time   `json:"last_updated,omitempty" bson:"last_updated,omitempty"`
	LastIndexCount    *int64       `json:"last_index_count,omitempty" bson:"last_index_count,omitempty"`
	LastSearched      *time.Time   `json:"last_searched,omitempty" bson:"last_searched,omitempty"`
	LastSearch        *time.Time   `json:"last_search,omitempty" bson:"last_search,omitempty"`
	Icon              *string      `json:"icon,omitempty" bson:"icon,omitempty"`

	RequiredScore *float64           `json:"required_score,omitempty" bson:"required_score,omitempty"`
	AssetType     *string            `json:"asset_type,omitempty" bson:"asset_type,omitempty"`
	Monitored     *bool              `json:"monitored,omitempty" bson:"monitored,omitempty"`
	IsThreatActor *bool              `json:"is_threat_actor,omitempty" bson:"is_threat_actor,omitempty"`
	Location      *AssetLocation     `json:"location,omitempty" bson:"location,omitempty"`
	Organization  *AssetOrganization `json:"organization,omitempty" bson:"organization,omitempty"`
	Emails        []*TagPair         `json:"emails,omitempty" bson:"emails,omitempty"`
	Phones        []*TagPair         `json:"phones,omitempty" bson:"phones,omitempty"`
	Urls          *Strings           `json:"urls,omitempty" bson:"urls,omitempty"`

	//domain
	Whois *AssetWhois `json:"whois,omitempty" bson:"whois,omitempty"`
	Mx    *Strings    `json:"mx,omitempty" bson:"mx,omitempty"`
	Ns    *Strings    `json:"ns,omitempty" bson:"ns,omitempty"`

	//person
	Brands *Strings
}

type TagPair struct {
	Tag   *string `json:"tag,omitempty" bson:"tag,omitempty"`
	Value *string `json:"value,omitempty" bson:"value,omitempty"`
}

type Event map[string]interface{}

type Case struct {
	ID         *string  `json:"id,omitempty" bson:"_id,omitempty"`
	Name       *string  `json:"name,omitempty" bson:"name,omitempty"`
	Evidence   *bool    `json:"evidence,omitempty" bson:"evidence,omitempty"`
	Emails     *Strings `json:"emails,omitempty" bson:"emails,omitempty"`
	AlertLevel *int64   `json:"alert_level,omitempty" bson:"alert_level,omitempty"`
	Group      *string  `json:"group,omitempty" bson:"group,omitempty"`
}

type Incident struct {
	ID           *string    `json:"id,omitempty" bson:"_id,omitempty"`
	Title        *string    `json:"title,omitempty" bson:"title,omitempty"`
	CaseName     *string    `json:"case_name,omitempty" bson:"case_name,omitempty"`
	Type         *string    `json:"type,omitempty" bson:"type,omitempty"`
	ClassifiedBy *string    `json:"classified_by,omitempty" bson:"classified_by,omitempty"`
	ClassifiedAt *time.Time `json:"classified_at,omitempty" bson:"classified_at,omitempty"`

	Description     *string `json:"description,omitempty" bson:"description,omitempty"`
	Recommendations *string `json:"recommendations,omitempty" bson:"recommendations,omitempty"`

	Date            *time.Time `json:"date,omitempty" bson:"date,omitempty"`
	CaseID          *string    `json:"case_id,omitempty" bson:"case_id,omitempty"`
	AssetID         *string    `json:"asset_id,omitempty" bson:"asset_id,omitempty"`
	ThreatActorName *string    `json:"threat_actor_name,omitempty" bson:"threat_actor_name,omitempty"`
	ThreatActorIDs  *Strings   `json:"threat_actor_ids,omitempty" bson:"threat_actor_ids,omitempty"`
	Source          *string    `json:"source,omitempty" bson:"source,omitempty"`
	Severity        *int64     `json:"severity,omitempty" bson:"severity,omitempty"`
	TargetIDs       *Strings   `json:"target_ids,omitempty" bson:"target_ids,omitempty"`
	TargetAssets    []*Asset   `json:"target_assets,omitempty" bson:"target_assets,omitempty"`
	Agent           *string    `json:"agent,omitempty" bson:"agent,omitempty"`
	Active          *bool      `json:"active,omitempty" bson:"active,omitempty"`
	Reported        *bool      `json:"reported,omitempty" bson:"reported,omitempty"`
	EventIDs        *Strings   `json:"event_ids,omitempty" bson:"event_ids,omitempty"`
	Events          []*Event   `json:"events,omitempty" bson:"events,omitempty"`
}

func UrlEncoded(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func ReuseMongo() error {
	var err error
	if MongoClient == nil {
		username := "stage"
		password := "GK!2f&Wf#z&RS3"

		password, err = UrlEncoded(password)
		if err != nil {
			return err
		}

		MongoClient, err = mongo.Connect(context.Background(), options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s@16.170.158.155:27017/?authSource=admin&readPreference=primary&ssl=false", username, password)))
		if err != nil {
			return err
		}
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

	return err
}

func Handler(rctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	//get incidents from last 30 days

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

		cases[*doc.ID] = doc
		case_ids = append(case_ids, *doc.ID)
	}

	if len(cases) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No cases found with provided group permissions").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	filter := map[string]interface{}{
		"case_id": map[string]interface{}{"$in": case_ids},
		"status":  map[string]interface{}{"$ne": "archived"},
	}

	q_cases, ok := request.QueryStringParameters["cases"]
	if ok {
		q_cases_arr := strings.Split(q_cases, ",")

		if len(q_cases_arr) > 0 {
			var cases_arr []string
			for _, id := range q_cases_arr {
				_, ok := cases[id]
				if ok {
					cases_arr = append(cases_arr, id)
				}
			}
			filter["case_id"] = map[string]interface{}{
				"$in": cases_arr,
			}
		}

	}

	df := time.Now().AddDate(0, 0, -30)

	filter["date"] = map[string]interface{}{
		"$gte": df,
	}

	filter["active"] = map[string]interface{}{
		"$eq": true,
	}

	res, err = MongoClient.Database("fyeo-di").Collection("incidents").Find(ctx, filter) //, options.Find().SetLimit(100))

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	var data []Incident
	for res.Next(ctx) {
		var doc Incident

		err := res.Decode(&doc)
		if err != nil {
			continue
		}

		doc.CaseName = cases[*doc.CaseID].Name

		data = append(data, doc)
	}

	if len(data) < 1 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       errors.New("No incidents found for the case IDs provided").Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	graphMap := make(map[string]map[int64]int64)

	for _, o := range data {
		if o.Severity != nil && o.Date != nil {
			_, ok := graphMap[o.Date.Format("2006-01-02")]
			if !ok {
				graphMap[o.Date.Format("2006-01-02")] = map[int64]int64{
					1: 0,
					2: 0,
					3: 0,
					4: 0,
					5: 0,
				}
			}
			_, ok = graphMap[o.Date.Format("2006-01-02")][*o.Severity]

			if ok {
				graphMap[o.Date.Format("2006-01-02")][*o.Severity] = 0
			}

			graphMap[o.Date.Format("2006-01-02")][*o.Severity]++
		}

	}

	for i := 0; i < 30; i++ {
		nd := df.AddDate(0, 0, 1)
		_, ok := graphMap[nd.Format("2006-01-02")]
		if !ok {
			graphMap[nd.Format("2006-01-02")] = map[int64]int64{
				1: 0,
				2: 0,
				3: 0,
				4: 0,
				5: 0,
			}
		}
	}

	js, err := json.Marshal(graphMap)

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
