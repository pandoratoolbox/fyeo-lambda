package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
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
	gMap        = make(map[string]bool)
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

type Case struct {
	ID           *string  `json:"id,omitempty" bson:"_id,omitempty"`
	Name         *string  `json:"name,omitempty" bson:"name,omitempty"`
	Evidence     *bool    `json:"evidence,omitempty" bson:"evidence,omitempty"` //not sure what this is for?
	Emails       *Strings `json:"emails,omitempty" bson:"emails,omitempty"`
	AlertLevel   *int64   `json:"alert_level,omitempty" bson:"alert_level,omitempty"`
	Group        *string  `json:"group,omitempty" bson:"group,omitempty"`
	ShouldNotify *bool    `json:"should_notify,omitempty" bson:"should_notify,omitempty"`
}

type Incident struct {
	ID           *string    `json:"id,omitempty" bson:"_id,omitempty"`
	Title        *string    `json:"title,omitempty" bson:"title,omitempty"`
	CaseName     *string    `json:"case_name,omitempty" bson:"case_name,omitempty"`
	Type         *string    `json:"type,omitempty" bson:"type,omitempty"`
	ClassifiedBy *string    `json:"classified_by,omitempty" bson:"classified_by,omitempty"`
	ClassifiedAt *time.Time `json:"classified_at,omitempty" bson:"classified_at,omitempty"`
	ClosedAt     *time.Time `json:"closed_at,omitempty" bson:"closed_at,omitempty"`

	Description *string `json:"description,omitempty" bson:"description,omitempty"` //used for summary?

	Recommendations *string `json:"recommendations,omitempty" bson:"recommendations,omitempty"`

	CreatedAt      *time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	CaseID         *string    `json:"case_id,omitempty" bson:"case_id,omitempty"`
	AssetID        *string    `json:"asset_id,omitempty" bson:"asset_id,omitempty"`
	ThreatActors   []*Asset   `json:"threat_actors,omitempty" bson:"-"`
	ThreatActorIDs *Strings   `json:"threat_actor_ids,omitempty" bson:"threat_actor_ids,omitempty"`
	Source         *string    `json:"source,omitempty" bson:"source,omitempty"`
	SourceType     *string    `json:"source_type,omitempty" bson:"source_type,omitempty"` //default to clear-net
	Severity       *int64     `json:"severity,omitempty" bson:"severity,omitempty"`
	TargetIDs      *Strings   `json:"target_ids,omitempty" bson:"target_ids,omitempty"`
	TargetAssets   []*Asset   `json:"target_assets,omitempty" bson:"-"`
	Agent          *string    `json:"agent,omitempty" bson:"agent,omitempty"`
	IsActive       *bool      `json:"is_active,omitempty" bson:"is_active,omitempty"`
	IsReported     *bool      `json:"is_reported,omitempty" bson:"is_reported,omitempty"`
	EventIDs       *Strings   `json:"event_ids,omitempty" bson:"event_ids,omitempty"`
	Events         []*Event   `json:"events,omitempty" bson:"-"`
}

type AssetNetloc struct {
	Cidr     *string `json:"cidr,omitempty" bson:"cidr,omitempty"`
	AsNumber *string `json:"as_number,omitempty" bson:"as_number,omitempty"`
}

type AssetWhois struct {
	Domain      *string    `json:"domain,omitempty" bson:"domain,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" bson:"expires_at,omitempty"`
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
	CreatedAt         *time.Time   `json:"created_at,omitempty" bson:"created_at,omitempty"`
	DumpSearchedAt    *time.Time   `json:"dump_searched_at,omitempty" bson:"dump_searched_at,omitempty"`
	SimilarSearchedAt *time.Time   `json:"similar_searched_at,omitempty" bson:"similar_searched_at,omitempty"`
	UpdatedAt         *time.Time   `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
	IndexCount        *int64       `json:"index_count,omitempty" bson:"index_count,omitempty"`
	SearchedAt        *time.Time   `json:"searched_at,omitempty" bson:"searched_at,omitempty"`
	IconURL           *string      `json:"icon_url,omitempty" bson:"icon_url,omitempty"`

	RequiredScore   *float64           `json:"required_score,omitempty" bson:"required_score,omitempty"`
	Type            *string            `json:"type,omitempty" bson:"type,omitempty"`
	IsActive        *bool              `json:"is_active,omitempty" bson:"is_active,omitempty"`
	IsThreatActor   *bool              `json:"is_threat_actor,omitempty" bson:"is_threat_actor,omitempty"`
	Location        *AssetLocation     `json:"location,omitempty" bson:"location,omitempty"`
	Organization    *AssetOrganization `json:"organization,omitempty" bson:"organization,omitempty"`
	Emails          []*TagPair         `json:"emails,omitempty" bson:"emails,omitempty"`
	PhoneNumbers    []*TagPair         `json:"phone_numbers,omitempty" bson:"phone_numbers,omitempty"`
	WalletAddresses []*TagPair         `json:"wallet_addresses,omitempty" bson:"wallet_addresses,omitempty"`
	Urls            *Strings           `json:"urls,omitempty" bson:"urls,omitempty"`

	//domain
	Whois *AssetWhois `json:"whois,omitempty" bson:"whois,omitempty"`
	Mx    *Strings    `json:"mx,omitempty" bson:"mx,omitempty"`
	Ns    *Strings    `json:"ns,omitempty" bson:"ns,omitempty"`

	//person
	Brands *Strings `json:"brands,omitempty" bson:"brands,omitempty"`

	IncidentCount *int64 `json:"incident_count,omitempty" bson:"-"`
}

type TagPair struct {
	Tag   *string `json:"tag,omitempty" bson:"tag,omitempty"`
	Value *string `json:"value,omitempty" bson:"value,omitempty"`
}

type Event struct {
	ID                *string    `json:"id,omitempty" bson:"_id,omitempty"`
	CaseID            *string    `json:"case_id" bson:"case_id,omitempty"`
	AssetID           *string    `json:"asset_id,omitempty" bson:"asset_id,omitempty"`
	IncidentID        *string    `json:"incident_id,omitempty" bson:"incident_id,omitempty"`
	Url               *string    `json:"url,omitempty" bson:"url,omitempty"`
	Title             *string    `json:"title,omitempty" bson:"title,omitempty"`
	SourceType        *string    `json:"source_type,omitempty" bson:"source_type,omitempty"`
	SourceContentType *string    `json:"source_content_type,omitempty" bson:"source_content_type,omitempty"`
	SourceNetwork     *string    `json:"source_network,omitempty" bson:"source_network,omitempty"`
	Type              *string    `json:"type,omitempty" bson:"type,omitempty"`
	Site              *string    `json:"site,omitempty" bson:"site,omitempty"`
	ThreatLevel       *int64     `json:"threat_level,omitempty" bson:"threat_level,omitempty"`
	CreatedAt         *time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	ConfidenceScore   *int64     `json:"confidence_score,omitempty" bson:"confidence_score,omitempty"`
}

type ErrorResponse struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func (data Asset) GetName() string {
	var name string
	if data.Name.Common != nil {
		name = *data.Name.Common
	} else {
		if data.Name.Last != nil {
			name = *data.Name.Last
		}

		if data.Name.Middle != nil {
			name += " " + *data.Name.Middle
		}

		if data.Name.First != nil {
			name += " " + *data.Name.First
		}
	}

	return name
}

func ServeError(message string, code int) events.APIGatewayProxyResponse {
	js, _ := json.Marshal(ErrorResponse{
		Code:    code,
		Message: message,
	})

	return events.APIGatewayProxyResponse{
		StatusCode: code,
		Body:       string(js),
		Headers:    defaultHeaders,
	}
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

func UrlEncoded(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func ReuseMongo() error {

	if MongoClient != nil {
		return nil
	} else {
		var err error
		username := "stage"
		password := "GK!2f&Wf#z&RS3"

		password, err = UrlEncoded(password)
		if err != nil {
			return err
		}

		ctx := context.Background()

		MongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s@192.168.0.17:27017/?authSource=admin&ssl=false", username, password)))
		if err != nil {
			return err
		}
	}

	return nil
}

func IsEmpty(input interface{}) bool {
	v := reflect.ValueOf(input)
	if v.IsZero() {
		return true
	}

	if v.Kind() == reflect.Ptr {
		if v.Elem().IsZero() {
			return true
		}

	}

	return false
}

func StructToBsonMap(input interface{}) (bson.M, error) {
	b, err := bson.Marshal(input)
	if err != nil {
		return bson.M{}, err
	}
	var data bson.M
	err = bson.Unmarshal(b, &data)
	if err != nil {
		return bson.M{}, err
	}

	delete(data, "_id")

	return data, nil
}

func GetCase(id string) (Case, error) {
	var out Case
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return out, err
	}

	filter := bson.M{"_id": o_id, "is_archived": bson.M{"$ne": true}}
	res := MongoClient.Database("fyeo-di").Collection("cases").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return out, res.Err()
	}

	err = res.Decode(&out)

	if err != nil {

		return out, err
	}

	return out, nil
}

func GetCases(filter bson.M) ([]Case, error) {
	var out []Case

	filter["is_archived"] = bson.M{"$ne": true}

	res, err := MongoClient.Database("fyeo-di").Collection("cases").Find(context.Background(), filter)

	if err != nil {
		return out, err
	}

	for res.Next(context.Background()) {
		var doc Case
		err := res.Decode(&doc)
		if err != nil {
			return out, err
		}
		out = append(out, doc)
	}

	return out, nil
}

func UpdateCase(id string, data Case) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.Group != nil {

		_, ok := gMap[*data.Group]

		if !ok {
			return errors.New("Unable to verify group permissions")
		}

	}

	current, err := GetCase(id)

	if err != nil {
		return err
	}

	if current.Group == nil {
		js, _ := json.Marshal(current)
		return errors.New(fmt.Sprintf("No group found for object: %s", string(js)))
	}

	_, ok := gMap[*current.Group]

	if !ok {
		return errors.New("Unable to verify group permissions")
	}

	update_data, err := StructToBsonMap(data)
	if err != nil {
		return err
	}

	update := bson.M{"$set": update_data}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("cases").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to update")
	}

	return nil
}

func NewCase(data *Case) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.Group != nil {

		_, ok := gMap[*data.Group]

		if !ok {
			return errors.New("Unable to verify group permissions")
		}

	} else {
		return errors.New("Object must contain group")
	}

	insert_data, err := StructToBsonMap(*data)
	if err != nil {
		return err
	}

	res, err := MongoClient.Database("fyeo-di").Collection("cases").InsertOne(context.Background(), insert_data)
	if err != nil {
		return err
	}

	nid := res.InsertedID.(primitive.ObjectID).Hex()

	data.ID = &nid

	return nil
}

func DeleteCase(id string) error {

	update := bson.M{"$set": bson.M{"is_archived": true}}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("cases").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to archive")
	}

	return nil
}

func GetIncident(id string) (Incident, error) {
	var out Incident
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return out, err
	}

	filter := bson.M{"_id": o_id}
	filter["is_archived"] = bson.M{"$ne": true}

	res := MongoClient.Database("fyeo-di").Collection("incidents").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return out, res.Err()
	}

	err = res.Decode(&out)

	if err != nil {
		return out, err
	}

	return out, nil
}

func GetIncidents(filter bson.M) ([]Incident, error) {
	var out []Incident

	filter["is_archived"] = bson.M{"$ne": true}

	res, err := MongoClient.Database("fyeo-di").Collection("incidents").Find(context.Background(), filter)

	if err != nil {
		return out, err
	}

	for res.Next(context.Background()) {
		var doc Incident
		err := res.Decode(&doc)
		if err != nil {
			return out, err
		}
		out = append(out, doc)
	}

	return out, nil
}

func GetIncidentsIDs(filter bson.M) ([]Incident, error) {
	var out []Incident

	filter["is_archived"] = bson.M{"$ne": true}

	res, err := MongoClient.Database("fyeo-di").Collection("incidents").Find(context.Background(), filter, options.Find().SetProjection(bson.M{"_id": 1}))

	if err != nil {
		return out, err
	}

	for res.Next(context.Background()) {
		var doc Incident
		err := res.Decode(&doc)
		if err != nil {
			return out, err
		}
		out = append(out, doc)
	}

	return out, nil
}

func UpdateIncident(id string, data Incident) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.CaseID != nil {
		ica, err := GetCase(*data.CaseID)

		if err != nil {
			return err
		}

		if !CasePermissions(ica) {
			return errors.New("Unable to verify case group permissions")
		}
	}

	current, err := GetIncident(id)

	if err != nil {
		return err
	}

	if current.CaseID == nil {
		js, _ := json.Marshal(current)
		return errors.New(fmt.Sprintf("No case ID found for object: %s", string(js)))
	}

	ca, err := GetCase(*current.CaseID)

	if err != nil {
		return err
	}

	if !CasePermissions(ca) {
		return errors.New("Unable to verify case group permissions")
	}

	update_data, err := StructToBsonMap(data)
	if err != nil {
		return err
	}

	update := bson.M{"$set": update_data}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("incidents").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to update")
	}

	return nil
}

func NewIncident(data *Incident) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.CaseID != nil {
		ica, err := GetCase(*data.CaseID)

		if err != nil {
			return err
		}

		if !CasePermissions(ica) {
			return errors.New("Unable to verify case group permissions")
		}

	} else {
		return errors.New("Object must contain case_id")
	}

	insert_data, err := StructToBsonMap(*data)
	if err != nil {
		return err
	}

	res, err := MongoClient.Database("fyeo-di").Collection("incidents").InsertOne(context.Background(), insert_data)
	if err != nil {
		return err
	}

	nid := res.InsertedID.(primitive.ObjectID).Hex()

	data.ID = &nid

	return nil
}

func DeleteIncident(id string) error {

	update := bson.M{"$set": bson.M{"is_archived": true}}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("incidents").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to archive")
	}

	return nil
}

func GetAsset(id string) (Asset, error) {
	var out Asset
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return out, err
	}

	filter := bson.M{"_id": o_id}
	filter["is_archived"] = bson.M{"$ne": true}

	res := MongoClient.Database("fyeo-di").Collection("assets").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return out, res.Err()
	}

	err = res.Decode(&out)

	if err != nil {

		return out, err
	}

	return out, nil
}

func GetAssets(filter bson.M) ([]Asset, error) {
	var out []Asset

	filter["is_archived"] = bson.M{"$ne": true}

	res, err := MongoClient.Database("fyeo-di").Collection("assets").Find(context.Background(), filter)

	if err != nil {
		return out, err
	}

	for res.Next(context.Background()) {
		var doc Asset
		err := res.Decode(&doc)
		if err != nil {
			return out, err
		}
		out = append(out, doc)
	}

	return out, nil
}

func UpdateAsset(id string, data Asset) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.CaseID != nil {
		ica, err := GetCase(*data.CaseID)

		if err != nil {
			return err
		}

		if !CasePermissions(ica) {
			return errors.New("Unable to verify case group permissions")
		}
	}

	current, err := GetAsset(id)

	if err != nil {
		return err
	}

	if current.CaseID == nil {
		js, _ := json.Marshal(current)
		return errors.New(fmt.Sprintf("No case ID found for object: %s", string(js)))
	}

	ca, err := GetCase(*current.CaseID)

	if err != nil {
		return err
	}

	if !CasePermissions(ca) {
		return errors.New("Unable to verify case group permissions")
	}

	update_data, err := StructToBsonMap(data)
	if err != nil {
		return err
	}

	update := bson.M{"$set": update_data}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("assets").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to update")
	}

	return nil
}

func NewAsset(data *Asset) error {

	if data.CaseID != nil {
		ica, err := GetCase(*data.CaseID)

		if err != nil {
			return err
		}

		if !CasePermissions(ica) {
			return errors.New("Unable to verify case group permissions")
		}

	} else {
		return errors.New("Object must contain case_id")
	}

	insert_data, err := StructToBsonMap(*data)
	if err != nil {
		return err
	}

	res, err := MongoClient.Database("fyeo-di").Collection("assets").InsertOne(context.Background(), insert_data)
	if err != nil {
		return err
	}

	nid := res.InsertedID.(primitive.ObjectID).Hex()

	data.ID = &nid

	return nil
}

func DeleteAsset(id string) error {

	update := bson.M{"$set": bson.M{"is_archived": true}}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("assets").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to archive")
	}

	return nil
}

func GetEvent(id string) (Event, error) {
	var out Event
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return out, err
	}

	filter := bson.M{"_id": o_id}
	filter["is_archived"] = bson.M{"$ne": true}

	res := MongoClient.Database("fyeo-di").Collection("events").FindOne(context.Background(), filter)

	if res.Err() != nil {
		return out, res.Err()
	}

	err = res.Decode(&out)

	if err != nil {

		return out, err
	}

	return out, nil
}

func GetEvents(filter bson.M) ([]Event, error) {
	var out []Event

	filter["is_archived"] = bson.M{"$ne": true}

	res, err := MongoClient.Database("fyeo-di").Collection("events").Find(context.Background(), filter)

	if err != nil {
		return out, err
	}

	for res.Next(context.Background()) {
		var doc Event
		err := res.Decode(&doc)
		if err != nil {
			return out, err
		}
		out = append(out, doc)
	}

	return out, nil
}

func UpdateEvent(id string, data Event) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.CaseID != nil {
		ica, err := GetCase(*data.CaseID)

		if err != nil {
			return err
		}

		if !CasePermissions(ica) {
			return errors.New("Unable to verify case group permissions")
		}
	}

	current, err := GetEvent(id)

	if err != nil {
		return err
	}

	if current.CaseID == nil {
		js, _ := json.Marshal(current)
		return errors.New(fmt.Sprintf("No case ID found for object: %s", string(js)))
	}

	ca, err := GetCase(*current.CaseID)

	if err != nil {
		return err
	}

	if !CasePermissions(ca) {
		return errors.New("Unable to verify case group permissions")
	}

	update_data, err := StructToBsonMap(data)
	if err != nil {
		return err
	}

	update := bson.M{"$set": update_data}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("events").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to update")
	}

	return nil
}

func NewEvent(data *Event) error {

	if IsEmpty(data) {
		return errors.New("Invalid input")
	}

	if data.CaseID != nil {
		ica, err := GetCase(*data.CaseID)

		if err != nil {
			return err
		}

		if !CasePermissions(ica) {
			return errors.New("Unable to verify case group permissions")
		}

	} else {
		return errors.New("Object must contain case_id")
	}

	insert_data, err := StructToBsonMap(*data)
	if err != nil {
		return err
	}

	res, err := MongoClient.Database("fyeo-di").Collection("events").InsertOne(context.Background(), insert_data)
	if err != nil {
		return err
	}

	nid := res.InsertedID.(primitive.ObjectID).Hex()

	data.ID = &nid

	return nil
}

func DeleteEvent(id string) error {

	update := bson.M{"$set": bson.M{"is_archived": true}}
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": o_id}
	res, err := MongoClient.Database("fyeo-di").Collection("events").UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	if res.MatchedCount < 1 {
		return errors.New("Unable to find the object to archive")
	}

	return nil
}

func CasePermissions(input Case) bool {
	if input.Group != nil {
		_, ok := gMap[*input.Group]
		return ok
	}

	return false
}

func VerifyRequest(request events.APIGatewayProxyRequest) error {

	claims := request.RequestContext.Authorizer["claims"]
	if claims == nil {
		return errors.New("No claims found for " + request.RequestContext.Identity.CognitoIdentityID)
	}

	rg := claims.(map[string]interface{})["cognito:groups"]

	if rg == nil {
		return errors.New("No group permissions set")
	}

	groups := strings.Split(rg.(string), ",")

	for _, g := range groups {
		gMap[g] = true
	}

	return nil
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error

	err = VerifyRequest(request)
	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	err = Init()
	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	id := request.PathParameters["id"]
	if id == "" {
		if err != nil {
			return ServeError("No ID provided", 400), nil
		}
	}

	asset, err := GetAsset(id)

	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	if asset.CaseID == nil {
		js, _ := json.Marshal(asset)
		return ServeError(fmt.Sprintf("No case ID found for object: %s", string(js)), 400), nil
	}

	ca, err := GetCase(*asset.CaseID)

	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	if !CasePermissions(ca) {
		return ServeError("Unable to verify case group permissions", 400), nil
	}

	err = DeleteAsset(id)
	if err != nil {
		return ServeError(err.Error(), 400), nil
	}

	return events.APIGatewayProxyResponse{
		Body:       "",
		StatusCode: 200,
		Headers:    defaultHeaders,
	}, nil
}
