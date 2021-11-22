package main

type IncidentDescription struct {
	ID             string `json:"_id" bson:"_id"`
	Severity       *int64
	Title          *string
	Recommendation *string
	BusinessImpact *string
	Class          *string
	Description    *string
}

type Case struct {
}

func (incident *Incident) Create() error {

	return nil
}

func GetIncidentTypes() ([]IncidentDescription, error) {
	var data []IncidentDescription
	//        self.incident_types = [incident_type for incident_type in self.mongo.incident_types.find()]
	//need to add incident_type collection to mongodb
	return data, nil
}

func GetEvents(filter map[string]interface{}) ([]Event, error) {
	var data []Event
	return data, nil
}

func GetCases(ids []string) ([]Case, error) {
	var out []Case

	return out, nil
}
