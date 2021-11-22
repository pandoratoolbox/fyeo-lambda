package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	DefaultDump        = false
	DefaultThreatActor = false
	DefaultThreatLevel = 3
)

type Strings []string

type Ints []int64

type Asset struct {
	ID          *string
	AssetType   *string
	Description *string
	Name        struct {
		Last   *string
		First  *string
		Common *string
	}
}

type ThreatActor struct {
	ID               *string
	Name             *string
	ThreatActorsList *Strings
	Description      *string
}

type Event struct {
	ID                 *string
	AssetID            *string
	ThreatActorsList   *Strings
	URL                *string
	Cuts               []*EventCut
	Agent              *string
	SourceContentType  *string
	SourceType         *string
	ParsedDates        *Strings
	MatcherPID         *int64
	OriginMatcher      *string
	CaseType           *string
	AssetName          *string
	AssetType          *string
	ConfidenceScore    *float64
	EventType          *string
	AssetMatches       *EventAssetMatch
	Version            *int64
	ThreatLevel        *int64
	Language           *string
	Languages          *Strings
	Time               *time.Time
	TranslatedTitle    *string
	SourceNetwork      *string
	IsTranslated       bool
	TranslationNeeded  bool
	TranslationWallet  *int64
	TranslationCounter *int64
	TranslatorVersion  *int64
	IsStared           bool
	IsSeen             bool
	IsAutoClassified   bool
	IsManClassified    bool
	StopAutoClassifier bool
	StaffStared        bool
	StaffSeen          bool
	StaffClassified    bool
	History            []struct {
		Action      *string
		ContentHash *string
		CutLen      *int64
		Date        *time.Time
		Informer    bool
	}
	Site          *string
	PageRank      *int64
	UrlHash       *string
	TitleHash     *string
	TranslateDate bool
	ManClassDate  bool
	AutoClassDate bool
	SeenDate      bool
	User          []struct{}
	Link          *Strings
	Email         *Strings
	IP            *Strings
	Hashtag       *Strings
	Keyword       *Strings
	Crypto        *Strings
	Target        *Strings
	CutCount      *int64
	UrlCnt        *int64
}

type EventAssetMatch struct {
	Position *Ints
	Term     *string
	CaseID   *string
	CaseType *string
	Match    struct {
		ID              string `json:"_id" bson:"_id"`
		KeywordType     *string
		AssetFieldCount *int64
		PerAssetType    struct {
			Name     *int64
			Location *int64
			Netloc   *int64
			Whois    *int64
		}
		AssetType       *string
		AssetCaseID     *string
		RequiredScore   *float64
		KeywordSource   *string
		AssetName       *string
		URL             *string
		ConfidenceScore *float64
	}
}

type EventCut struct {
	Matched struct {
		Standalone    bool
		Required      bool
		Entity        struct{}
		SearchTerm    *string
		Expression    *string
		Info          *string
		AssetID       *string
		IsThreatActor bool
	}
	Base              *string
	Type              *string
	Tags              *Strings
	Cut               *string
	Len               *int64
	LineHash          *string
	HashVersion       *int64
	TagsMax           *int64
	PotentialKeywords *Strings
}

type Incident struct {
	ZendeskTicketID *string    `json:"zendesk_ticket_id" bson:"zendesk_ticket_id"`
	ID              *string    `json:"id" bson:"_id"`
	Source          *string    `json:"source" bson:"source"`
	Title           *string    `json:"title" bson:"title"`
	Class           *string    `json:"class" bson:"class"`
	ClassifiedBy    *string    `json:"classified_by" bson:"classified_by"`
	Severity        *int64     `json:"severity" bson:"severity"`
	AssetID         *string    `json:"asset_id" bson:"asset_id"`
	CaseID          *string    `json:"case_id" bson:"parent_id"`
	Events          *Strings   `json:"events" bson:"events"` //array of event IDs
	Description     *string    `json:"description" bson:"description"`
	Recommendations *string    `json:"recommendations" bson:"recommendations"`
	ThreatActorName *string    `json:"threat_actor_name" bson:"threat_actor_name"`
	ThreatActorId   *string    `json:"thread_actor_id" bson:"threat_actor_id"`
	Targets         *Strings   `json:"targets" bson:"targets"`
	Group           *string    `json:"group" bson:"group"`
	ReportedDate    *time.Time `json:"reported_date" bson:"reported_date"`
	ClosedDate      *time.Time `json:"closed_date" bson:"closed_date"`
	ClassifiedDate  *time.Time `json:"classified_date" bson:"classified_date"`
	UpdatedDate     *time.Time `json:"updated_date" bson:"updated_date"`
	Date            *time.Time `json:"date" bson:"date"`
	IsActive        *bool      `json:"is_active" bson:"is_active"`
	IsReported      *bool      `json:"is_reported" bson:"is_reported"`
	Agent           *string    `json:"agent" bson:"agent"`
	// Case              Case          `json:"case"`
	// Asset Asset json:"asset"
	//AssetName *string `json:"asset_name" bson:"asset_name"`
	CaseName *string `json:"case_name" bson:"case_name"`
}

type RuleParams struct {
	IsManClassified bool
	IncidentType    string
	ThreatActor     bool
	Dump            bool
	ThreatLevel     *int
}

type Rule struct {
	Name   string
	Filter *RuleFilter
	Action *string
	Update *Event
	Params *RuleParams
}

type RuleFilter map[string]interface{} //should be a bson.Map

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

func main() {

	rules, err := GetRules("rules.yaml")

	if err != nil {
		log.Fatal(err)
	}

	for _, rule := range rules {
		filter := make(map[string]interface{})
		filter["isManClassified"] = false
		filter["time"] = map[string]interface{}{
			"$gt": time.Now().AddDate(0, 0, -7),
		}

		if *rule.Action == "update" {
			UpdateEvents(filter, rule)
		}

		if *rule.Action == "incident" {
			events, err := GetEvents(filter)
			if err != nil {
				log.Fatal(err)
			}

			threat_level := 3

			if rule.Params.ThreatLevel != nil {
				threat_level = *rule.Params.ThreatLevel
			}

			for _, event := range events {
				if event.ThreatActorsList != nil {
					is_threat_actor := false

					for _, l := range *event.ThreatActorsList {
						if l == *event.AssetID {
							is_threat_actor = true
						}
					}

					if is_threat_actor {
						event.Classify(3, rule.Name)
						continue
					}
				}

				event.Classify(threat_level, rule.Name)

				incident := Incident{
					ThreatActorId: &[]string(*event.ThreatActorsList)[0],
				}

				err = incident.Create()
				if err != nil {
					log.Fatal(err)
				}

				// """
				// this function creates an incident bases
				// :param event:
				// :param incident_type:
				// :return:
				// """
				// if dump:
				// 	source = getDumpSource(event)

				// elif incident_type in ['similar_domain', 'existing_similar_domain']:
				// 	try:
				// 		source = event.get('url').split('/')[4]
				// 	except IndexError:
				// 		source = event.get('url').split('/')[3]
				// elif incident_type == 'new_cert_discovered' or incident_type == "new_multi_cert":
				// 	source = self.get_source_cert(event)
				// else:
				// 	source = event.get('site')

				// incident_template = next(item for item in self.incident_types if item["class"] == incident_type)

				// if threat_actor:
				// 	threat_actor_info = self.get_threat_actor_info(event.get('threat_actors_list')[0])
				// 	threat_actor_name = get_name_for_threat_actor(threat_actor_info)
				// 	title = incident_template.get('title') % (event.get('asset_name', "asset"), source, threat_actor_name)
				// 	threat_actor_id = str(event.get('threat_actors_list')[0])

				// else:
				// 	threat_actor = ''
				// 	threat_actor_id = ''
				// 	title = incident_template.get('title') % (event.get('asset_name', "asset"), source)

				// inc_data = {
				// 	'title': title,
				// 	"case_Name": '',
				// 	"class": incident_type,
				// 	'type': incident_type,
				// 	"classifiedBy": 'intelliagg.com',
				// 	"parentId": event.get('caseId'),
				// 	"asset_id": event.get('asset_id'),
				// 	"classifiedDate": event['time'],
				// 	"description": incident_template.get('description'),
				// 	"recommendations": incident_template.get('recommendation'),
				// 	"threat_actor": threat_actor,
				// 	"threat_actor_id": threat_actor_id,
				// 	"source": "%s" % source,
				// 	"date": event.get('time'),
				// 	"severity": int(incident_template.get('severity')),
				// 	"targets": [event.get('asset_name')],
				// 	"agent": 'rules_engine',
				// 	"active": True,
				// 	"reported": False
				// }
				// existing_incident = self.mongo.incidents.find_one(
				// 	{'parentId': inc_data['parentId'], 'source': inc_data['source'], 'title': {"$regex": inc_data['title'][:15]}})
				// if existing_incident:
				// 	_id = existing_incident['_id']
				// else:
				// 	logging.info('creating incident: %s [%s]' % (inc_data['title'], inc_data['date']))
				// 	_id = self.mongo.incidents.insert_one(inc_data).inserted_id

				// self.add_to_incident(_id, event)

			}

		}

	}

	AutoCloseKnownWhois()

}

func AutoCloseKnownWhois() error {
	res, err := MongoClient.Database("fyeo-di").Collection("incidents").Find(context.Background(), bson.M{"type": "similar_domain", "active": true})
	if err != nil {
		return err
	}

	for res.Next(context.Background()) {
		var doc Incident

		err := res.Decode(&doc)
		if err != nil {
			return err
		}

		if doc.Source != nil {

			if strings.HasSuffix(*doc.Source, []string(*doc.Targets)[0]) {
				o_id, err := primitive.ObjectIDFromHex(*doc.ID)
				if err != nil {
					//err
				}
				res, err := MongoClient.Database("fyeo-di").Collection("incidents").UpdateOne(context.Background(), bson.M{"_id": o_id}, bson.M{"$set": bson.M{"active": false, "recommendations": "closed since it is a known subdomain", "closed_date": time.Now()}})
				if err != nil {
					return err
				}
				if res.UpsertedID == nil {
					return errors.New("Unable to update close incident with known WHOIS")
				}
			}

		} else {
			return errors.New("Unable to get source from incident " + *doc.ID)
		}
	}

	return nil
	// incidents = mongo.tf.incidents.find({'type': "similar_domain", 'active': True})

	// for incident in incidents:
	// 	source = incident.get('source', '')
	// 	target = incident.get('targets')[0]
	// 	if source.endswith(target):
	// 		mongo.tf.incidents.update_one({"_id": incident.get('_id')},
	// 									  {"$set": {'active': False,
	// 												'recommendations': 'closed since it is a known subdomain',
	// 												'closed_date': datetime.now()
	// 												}})
}

func GetRules(path string) ([]Rule, error) {
	var data []Rule
	return data, nil
}

func (event *Event) Classify(threat_level int, rule_name string) error {
	// 	action = {"action": "auto-classed",
	// 	"user": "rules-engine",
	// 	"date": datetime.now(),
	// 	"threatLevel": threat_level,
	// 	"rule": rule}

	// res = mongo.tf.events.update_one({"_id": event['_id']},
	// 						   {"$set": {"isManClassified": True, "isAutoClassified": True,
	// 									 'threat_level': threat_level},
	// 							"$push": {'history': action}})

	data := bson.M{
		"action":      "auto-classed",
		"user":        "rules-engine",
		"date":        time.Now(),
		"threatLevel": threat_level,
		"rule":        rule_name,
	}

	o_id, err := primitive.ObjectIDFromHex(*event.ID)
	if err != nil {
		return err
	}

	update := bson.M{"$set": bson.M{"isManClassified": true, "isAutoClassified": true, "threat_level": threat_level}, "$push": bson.M{"history": data}}

	filter3 := bson.M{"_id": o_id}
	res3, err := MongoClient.Database("fyeo-di").Collection("incidents").UpdateOne(context.Background(), filter3, update)

	if err != nil {
		return err
	}

	if res3.ModifiedCount < 1 {
		return errors.New("Unable to classify event and update incident")
	}

	return nil
}

func GetThreatActorInfo(id string) (ThreatActor, error) {
	var out ThreatActor
	o_id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return out, err
	}

	res := MongoClient.Database("fyeo-di").Collection("assets").FindOne(context.Background(), bson.M{"_id": o_id, "is_threat_actor": true})
	if res.Err() != nil {
		return out, res.Err()
	}

	var doc Asset
	res.Decode(&out)

	if *doc.AssetType == "domain" || *doc.AssetType == "organisation" {

	}

	if *doc.AssetType == "person" {

	}

	var name string

	switch *doc.AssetType {
	case "organisation":
		name = *doc.Name.Common
		break
	case "domain":
		name = *doc.Name.Common
		break
	case "person":
		name = fmt.Sprintf("%s %s", doc.Name.Last, doc.Name.First)
		break
	default:
		name = "unknown"
		break
	}

	return ThreatActor{
		Name:        &name,
		Description: doc.Description,
	}, nil
	// ta = self.assets.find_one({'_id': _id, 'is_threat_actor': True})
	// if ta == None:
	// 	return False
	// if ta['asset_type'] in ['domain', 'organisation']:
	// 	name = ta.get('name', {}).get('common')
	// elif ta['asset_type'] == 'person':
	// 	name = "%s %s" % (ta.get('name').get('last'), ta.get('name').get('first'))
	// else:
	// 	name = 'unkown'

	// return {'name': name, 'description': ta.get('description', '')}
}

func (threat_actor_info *ThreatActor) GetName() string {
	if threat_actor_info.Name != nil {
		return *threat_actor_info.Name
	} else {
		return "unknown"
	}
}

func (event *Event) GetDumpSource() {

	// url = event.get('url')
	// try:
	//     source = url.split("/")[3]
	// except Exception:
	//     source = 'NA'
	// return source
}

func (event *Event) GetSourceCert() string {

	if event.URL != nil {
		data := strings.Split(*event.URL, "/")

		if len(data) > 4 {
			return data[4]
		}
	}

	cut := event.Cuts[0].Cut

	//regex not working
	rxp := regexp.MustCompile(`\'[0-9a-z\.]*\.[a-z]*\'`)

	sources := rxp.FindAll([]byte(*cut), -1)

	for _, s := range sources {
		res := strings.ReplaceAll(string(s), "\\'", "")
		res = strings.ReplaceAll(res, "'", "")
		if res != *event.Cuts[0].Matched.SearchTerm {
			return res
		}
	}

	return ""
}

func (rule *Rule) Apply() {
	params := RuleParams{
		ThreatActor: DefaultThreatActor,
		Dump:        DefaultDump,
	}

	// 	for rule in self.rules:
	// 	q = copy.copy(self.base_query)

	// 	for key, value in rule.get('filter', {}).items():
	// 		q[key] = value

	// 	if rule.get('action') == 'update':
	// 		self.update_events(q, rule)
	// 		continue

	// 	if rule.get('action') == 'incident':
	// 		rule_params = rule.get('params', {})
	// 		events = self.mongo.events.find(q)
	// 		print ("[%s]: %s" %(rule.get('name'), events.count()))
	// 		threat_level = rule_params.get('threat_level', 3)
	// 		for event in events:
	// 			if ObjectId(event['asset_id']) in event.get('threat_actors_list', []):
	// 				classify_event(event, threat_level=3, rule=rule.get('name'))
	// 				continue

	// 			threat_actor = rule_params.get('threat_actor', False)
	// 			incident_type = rule_params.get('incident_type')
	// 			dump = rule_params.get('dump', False)

	// 			classify_event(event, threat_level, rule=rule.get('name'))
	// 			self.createIncident(event, incident_type, threat_actor=threat_actor, dump=dump)

	// self.auto_close_known_whois()

}

type EventHistory struct {
	Action string
	User   string
	Date   time.Time
	Rule   string
}

func UpdateEvents(filter map[string]interface{}, rule Rule) {

	// update = rule.get('update', {})
	// rule_name = rule.get('name', '?')
	// res = self.mongo.events.update_many(q, {"$set": update})
	// res = self.mongo.events.update_many(q,
	// 									{"$push":
	// 										{'history':
	// 											{
	// 												"action": "auto-classed",
	// 												"user": "rules-engine",
	// 												"date": datetime.now(),
	// 												"rule": rule_name
	// 											}
	// 										}
	// 									})

	//update events which match filter with new data
	//push to event history

	update2 := map[string]interface{}{
		"$push": map[string]interface{}{
			"history": map[string]interface{}{
				"action": "auto-classed",
				"user":   "rules-engine",
				"date":   time.Now(),
				"rule":   rule.Name,
			},
		},
	}
}

func (event *Event) AddToIncident(id string) {

	// def add_to_incident(self, incident_id, event):
	// """
	// :param incident_id:
	// :param event:
	// :return:
	// """
	// try:
	// 	res = self.mongo.incidents.update_one({'_id': ObjectId(incident_id)},
	// 										  {'$addToSet': {'events': str(event.get('_id')),
	// 														 'targets': event.get('asset_name')}})
	// except Exception as e:
	// 	logging.exception(e)
	// 	return
	// self.mongo.events.update_one({'_id': event['_id']},
	// 							 {'$set': {'incident': str(incident_id), 'isManClassified': True}})

	// return res
}

//get events
//get rules from json
//iterate over rules
//create incidents from events according to rule
//if rule matches, invoke action with specified params
//set default params
//execute action - save incident (and threat actor if specified)
