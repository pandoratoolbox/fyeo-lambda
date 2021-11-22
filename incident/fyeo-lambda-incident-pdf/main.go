package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	cognitoidentity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	OUTPUT_PATH         = "/tmp/sample.pdf"
	AWS_INCIDENT_BUCKET = "fyeo-s3-incident-report"
	IDENTITY_POOL_ID    = "eu-north-1:1b10f408-50a9-4204-9194-c143fdb03278"

	//S3 OBJECT KEY = INCIDENT ID?
	Cognito     *cognito.Client
	CognitoID   *cognitoidentity.Client
	MongoClient *mongo.Client
	S3Client    *s3.Client
	StsClient   *sts.Client

	defaultHeaders = map[string]string{
		"Content-Type":                 "application/json",
		"Access-Control-Allow-Headers": "*",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, OPTIONS, POST",
		"Allow":                        "GET, OPTIONS, POST",
	}

	style = `<style>
	a, a:link, a:visited, a:active, a:hover {
	  text-decoration: none;
	  border:0!important;
	}
	.doc {
	  width: 100%;
	  min-height: 100%;
	  /* height: 842px; */
	 align-items: center;
	  display: flex;
	  flex-direction: column;
	}
	.header {
		width: 100%;
	  padding-top: 21px;
	  padding-bottom: 15px;
	  padding-left: 42px;
	  background: linear-gradient(95.18deg, #3ead40 12.45%, #f9c704 96.55%);
	  color: rgb(255, 255, 255);
	  font-size: 24px;
	  font-weight: 700;
	}
	.header-logo {
	  height: 24px;
	  width: 83px;
	  background-size: cover;
	  background-image: url("images/logo.svg");
	  margin-bottom: 5px;
	}
	.content {
	  padding-left: 35px;
	  padding-right: 35px;
	  padding-top: 25px;
	  padding-bottom: 28px;
	}
  
	.content-title {
	  color: rgb(0, 0, 0);
	  font-size: 18px;
	  font-weight: 700;
	}
  
	.content-summary {
	  margin-top: 8px;
	  font-weight: 400;
	  font-size: 12px;
	}
  
	.content-data {
	  margin-top: 24px;
	  display: flex;
	  flex-direction: row;
	}
  
	.content-data-fields {
	  display: flex;
	  flex-direction: column;
	  border-radius: 5px;
	  padding-left: 24px;
	  padding-top: 8px;
	  padding-bottom: 8px;
	  background: #f8f9fb;
	}
  
	.content-data-fields-row-first {
	  font-size: 12px;
	  font-weight: 400;
	  display: flex;
	  flex-direction: row;
	}
  
	.content-data-fields-row {
	  font-size: 12px;
	  font-weight: 400;
	  display: flex;
	  flex-direction: row;
	  margin-top: 4px;
	}
  
	.content-data-fields-row-name {
	  display: flex;
	  flex-direction: column;
	  font-weight: 600;
	  width: 30%;
	}
  
	.content-data-fields-row-value {
	  display: flex;
	  flex-direction: column;
	}
  
	.content-data-severity {
	  display: flex;
	  flex-direction: column;
	  border-radius: 5px;
	  width: 106px;
	  height: 111px;
	  background: #f8f9fb;
	  margin-left: 12px;
	  justify-content: center;
	  align-items: center;
	  margin-top: 4px;
	}
  
	.content-data-severity-icon-low {
	  width: 37px;
	  height: 37px;
	  background-size: cover;
	  background-image: url("images/severity_low.svg");
	}
  
	.content-data-severity-text {
	  text-transform: capitalize;
	  margin-top: 4px;
	  font-weight: 400;
	  font-size: 12px;
	}
  
	.content-threat-actor {
	  margin-top: 12px;
	}
  
	.content-threat-actor-title {
	  font-size: 12px;
	  font-weight: 600;
	}
  
	.content-threat-actor-field {
	  margin-top: 2px;
	  background: #f8f9fb;
	  height: 36px;
	  font-size: 12px;
	  flex-direction: row;
	  display: flex;
	  align-items: center;
	  padding-left: 20px;
	  padding-right: 20px;
	}
  
	.content-threat-actor-field-icon {
		width: 19px;
		height: 19px;
		background-image: url("images/domain_threat_actor.svg");
		background-size: cover;
		margin-right: 12px;
	}
  
	.content-targets {
	  margin-top: 14px;
	}
  
	.content-targets-title {
	  font-weight: 600;
	  font-size: 12px;
	}
  
	.content-targets-data {
	  margin-top: 2px;
	  background: #f8f9fb;
	  border-radius: 5px;
	  padding-left: 20px;
	  padding-right: 20px;
	  flex-direction: column;
	  display: flex;
	  padding-top: 13px;
	  padding-bottom: 13px;
	}
  
	.content-targets-data-row-first {
	  flex-direction: row;
	  display: flex;
	  align-items: center;
	  font-size: 12px;
	  vertical-align: baseline;
	}
  
	.content-targets-data-row {
	  flex-direction: row;
	  display: flex;
	  align-items: center;
	  font-size: 12px;
	  margin-top: 12px;
  
	}
  
	.content-targets-data-row-icon {
		display: flex;
		flex-direction: column;
	  width: 19px;
		height: 19px;
		background-image: url("images/person.svg");
		background-size: cover;
		margin-right: 12px;
	}
  
	.content-targets-data-row-name {
	  display: flex;
		flex-direction: column;
		width: 50%;
	}
  
	.content-targets-data-row-meta {
	  display: flex;
		flex-direction: column;
		flex-grow: 2;
	}
  
	.content-targets-data-row-cta {
	  display: flex;
		flex-direction: column;
		justify-self: flex-end;
		align-self: flex-end;
		align-items: center;
		justify-content: center;
		width: 14px;
		height: 13px;
		background-image: url("images/link_active.svg");
		background-size: cover;
		cursor: pointer;
	}
	.content-targets-data-row-cta-img {
	  width: 14px;
		height: 13px;
		background-image: url("images/link_active.svg");
		background-size: cover;
	}
  
	.content-cta {
		margin-top: 19px;
	  display: flex;
	  flex-direction: row;
	  justify-content: center;
	}
  
	.content-cta-button {
	  background: #31ad34;
	  border: 2px solid #31ad34;
	  box-sizing: border-box;
	  border-radius: 2px;
	  height: 33px;
	  width: 198px;
	  justify-content: center;
	  align-items: center;
	  display: flex;
	  flex-direction: column;
	  cursor: pointer;
	  font-size: 15px;
	}
  
	.content-cta-button-text {
	  color: #FFFFFF;
	  font-size: 15px;
	  font-weight: 700;
	}
  
	.footer {
		justify-self: flex-end;
		width: 100%;
		display: flex;
		flex-direction: row;
	  padding-left: 17px;
		  height: 33px;
	  background: linear-gradient(95.18deg, #3ead40 12.45%, #f9c704 96.55%);
	  color: rgb(255, 255, 255);
	  font-size: 12px;
	  font-weight: 500;
	  align-items: center;
	}
  
  .content-recommendations-title {
  font-weight: 700;
  font-size: 18px;
  }
  .content-recommendations-data {
  font-weight: 400;
  font-size: 12px;
  margin-top: 8px;
  }
  
  .content-events {
  margin-top: 32px;
  margin-bottom: 32px;
  }
  
  .content-events-title {
  font-weight: 700;
  font-size: 18px;
  }
  
  .content-events-data-first {
  display: flex;
  flex-direction: row;
  margin-top: 16px;
  padding-top: 16px;
  padding-bottom: 16px;
  padding-left: 16px;
  padding-right: 16px;
  margin-bottom: 10px;
  background: #F8F9FB;
  border-radius: 4px;
  align-items: center;
  font-size: 12px;
  }
  
  .content-events-data {
  display: flex;
  flex-direction: row;
  padding-top: 16px;
  padding-bottom: 16px;
  padding-left: 16px;
  padding-right: 16px;
  width: 524px;
  margin-bottom: 10px;
  background: #F8F9FB;
  border-radius: 4px;
  align-items: center;
  }
  
  .content-events-data-icon {
  display: flex;
  flex-direction: column;
  width: 45px;
  height: 45px;
  background: #C4C4C4;
  border-radius: 2px;
  margin-right: 16px;
  }
  
  .content-events-data-value {
  display: flex;
  flex-direction: column;
  flex-grow: 2;
  font-weight: 500;
  }
  
  .content-events-data-date {
  display: flex;
  flex-direction: column;
  }
  
  .content-events-data-cta {
  
  }
  
  </style>`

	html = `<html>
	{{page_1}}
	{{page_2}}
	</html>
	` + style
)

type Asset struct {
	ID   string `json:"id" bson:"_id"`
	Name *struct {
		Common *string `json:"common" bson:"common"`
		First  *string `json:"first" bson:"first"`
		Middle *string `json:"middle" bson:"middle"`
		Last   *string `json:"last" bson:"last"`
	} `json:"name" bson:"name"`
	IsThreatActor     *bool      `json:"is_threat_actor" bson:"is_threat_actor"`
	AssetCreationDate *time.Time `json:"asset_creation_date" bson:"asset_creation_date"`
	Icon              *string    `json:"icon" bson:"icon"`
}

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
	S3Key *string `json:"s3_key" bson:"s3_key"`
	// S3Link *string `json:"s3_link" bson:"s3_link"`
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

	AssetName *string `json:"asset_name"`
	CaseName  *string `json:"case_name"`

	Assets       []Asset `json:"assets"`
	EventObjects []Event `json:"event_objects"`
}

type Event struct {
	Title       *string `json:"title" bson:"title"`
	Asset       *Asset  `json:"asset"`
	AssetID     *string `json:"asset_id" bson:"asset_id"`
	Time        *time.Time
	ThreatLevel *int64 `json:"threat_level" bson:"threat_level"`
}

func main() {
	// path, err := os.Getwd()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	// defer cancel()

	// allocCtx, cancel := chromedp.NewContext(ctx)
	// defer cancel()

	// ctx, cancel = chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	// defer cancel()

	// var buf []byte

	// if err := chromedp.Run(ctx, printToPDF("file:///"+path+"/source/test.html", &buf)); err != nil {
	// 	log.Fatal(err)
	// }

	// os.RemoveAll("test.pdf")
	// if err := ioutil.WriteFile("test.pdf", buf, 0777); err != nil {
	// 	log.Fatal(err)
	// }

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

	err = ReuseS3()
	if err != nil {
		return err
	}

	err = ReuseCognitoIdentity()
	if err != nil {
		return err
	}

	err = ReuseSts()
	if err != nil {
		return err
	}

	return err
}

func ReuseSts() error {
	if StsClient != nil {
		return nil
	} else {
		var err error
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return err
		}
		StsClient = sts.NewFromConfig(cfg)

	}

	return nil

}

func ReuseCognitoIdentity() error {
	if CognitoID != nil {
		return nil
	} else {
		var err error
		cfg, err := config.LoadDefaultConfig(context.TODO())
		CognitoID = cognitoidentity.NewFromConfig(cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

func ReuseS3() error {
	var err error
	cfg, err := config.LoadDefaultConfig(context.TODO())
	S3Client = s3.NewFromConfig(cfg)
	if err != nil {
		return err
	}

	return nil
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
			Body:       res.Err().Error() + " for " + o_id.String(),
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

	if res2.Err() != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       res2.Err().Error() + ": " + *out.CaseID,
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

	asset_id, err := primitive.ObjectIDFromHex(*out.AssetID)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	res3 := MongoClient.Database("fyeo-di").Collection("assets").FindOne(context.Background(), bson.M{"_id": asset_id})

	if res3.Err() != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       res3.Err().Error() + " for " + o_id.String(),
			Headers:    defaultHeaders,
		}, nil
	}

	var asset Asset
	err = res3.Decode(&asset)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	out.Assets = []Asset{asset}

	if out.Events != nil {
		res4, err := MongoClient.Database("fyeo-di").Collection("events").Find(context.Background(), bson.M{"_id": bson.M{"$in": []string(*out.Events)}})
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       err.Error(),
				Headers:    defaultHeaders,
			}, nil
		}

		var event_objects []Event
		for res4.Next(ctx) {
			var eobj Event
			err := res4.Decode(&eobj)
			if err != nil {
				return events.APIGatewayProxyResponse{
					StatusCode: 400,
					Body:       err.Error(),
					Headers:    defaultHeaders,
				}, nil
			}

			if eobj.AssetID != nil {
				res := MongoClient.Database("fyeo-di").Collection("assets").FindOne(context.Background(), bson.M{"_id": *eobj.AssetID})
				if res.Err() != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: 400,
						Body:       res.Err().Error(),
						Headers:    defaultHeaders,
					}, nil
				}

				var e_asset Asset

				err := res.Decode(&e_asset)
				if err != nil {
					return events.APIGatewayProxyResponse{
						StatusCode: 400,
						Body:       err.Error(),
						Headers:    defaultHeaders,
					}, nil
				}

				eobj.Asset = &e_asset
			}

			event_objects = append(event_objects, eobj)

		}

		out.EventObjects = event_objects
	}

	err = Export(out)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	_, err = SaveS3(*out.ID+".pdf", OUTPUT_PATH)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	psClient := s3.NewPresignClient(S3Client)
	psresp, err := psClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(AWS_INCIDENT_BUCKET),
		Key:    aws.String(*out.ID + ".pdf"),
	})

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       err.Error(),
			Headers:    defaultHeaders,
		}, nil
	}

	js, err := json.Marshal(struct {
		S3Link string `json:"s3_link"`
	}{
		S3Link: psresp.URL,
	})

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

func SaveS3(name string, path string) (string, error) {
	b, err := os.Open(path)
	if err != nil {
		return "", err
	}

	uploader := manager.NewUploader(S3Client)

	_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(AWS_INCIDENT_BUCKET),
		Key:    aws.String(name),
		Body:   b,
	})

	if err != nil {
		return "", err
	}

	return name, nil
}

func CopyFolder(source, destination string) error {
	err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		_, err2 := ioutil.ReadFile(path)
		if err2 != nil {
			return err2
		}

		return nil
	})
	return err
}

func Page2(input Incident) string {
	var out = `
	<div class="doc" style="page-break-before: always;">
        <div class="header"><div class="header-logo"></div>Incident report</div>
<div class="content">
    <div class="content-recommendations">
        <div class="content-recommendations-title">
            Recommendations
        </div>
        <div class="content-recommendations-data">
            {{recommendations}}
        </div>
    </div>
    {{events}}
</div>
<div style="display:flex; flex-direction: column; flex-grow: 2;"></div>
<div class="footer">{{today_date}}</div>
</div>`
	events := `<div class="content-events">
<div class="content-events-title">
	Events in incident
</div>
%s
</div>`
	var rows string
	for i, v := range input.EventObjects {
		if i == 0 {
			rows += fmt.Sprintf(`<div class="content-events-data-first">
		<div class="content-events-data-icon">
	
		</div>
		<div class="content-events-data-value">
			%s
		</div>
		<div class="content-events-data-date">
			%s
		</div>
		<div class="content-events-data-cta">
	
		</div>
	</div>`, *v.Title, v.Time.Format("2006-01-02"))
			continue
		}
		rows += fmt.Sprintf(`<div class="content-events-data">
		<div class="content-events-data-icon">
	
		</div>
		<div class="content-events-data-value">
			%s
		</div>
		<div class="content-events-data-date">
			%s
		</div>
		<div class="content-events-data-cta">
	
		</div>
	</div>`, *v.Title, v.Time.Format("2006-01-02"))
	}

	events = fmt.Sprintf(events, rows)

	out = strings.Replace(out, "{{recommendations}}", *input.Recommendations, 1)

	out = strings.Replace(out, "{{events}}", events, 1)

	out = strings.Replace(out, "{{today_date}}", time.Now().Format("2006-01-02"), 1)

	return out
}

func Page1(input Incident) string {

	txt := `<div class="doc">
    <div class="header"><div class="header-logo"></div>Incident report</div>
    <div class="content">
      <div class="content-title">
{{title}}
      </div>
      <div class="content-summary">
{{summary}}
      </div>
      <div class="content-data">
        <div class="content-data-fields">
          <div class="content-data-fields-row-first">
            <div class="content-data-fields-row-name">Case</div>
            <div class="content-data-fields-row-value">
{{case_name}}
            </div>
          </div>
          <div class="content-data-fields-row">
            <div class="content-data-fields-row-name">Incident Type</div>
            <div class="content-data-fields-row-value">
              {{type}}
            </div>
          </div>
          <div class="content-data-fields-row">
            <div class="content-data-fields-row-name">Date</div>
            <div class="content-data-fields-row-value">{{date}}</div>
          </div>
          <div class="content-data-fields-row">
            <div class="content-data-fields-row-name">Source</div>
            <div class="content-data-fields-row-value">{{source}}</div>
          </div>
          <div class="content-data-fields-row">
            <div class="content-data-fields-row-name">Status</div>
            <div class="content-data-fields-row-value">{{status}}</div>
          </div>
        </div>
        <div class="content-data-severity">
          <div class="content-data-severity-icon-low"></div>
          <div class="content-data-severity-text">{{severity_level}}</div>
        </div>
      </div>
      {{threat_actor}}
      {{targets}}
      <div class="content-cta">
          <div class="content-cta-button">
           <div class="content-cta-button-text">View Incident in Portal</div>
          </div>
      </div>
    </div>
    <div style="display:flex; flex-direction: column; flex-grow: 2;"></div>
    <div class="footer">{{today_date}}</div>
  </div>`

	threat_actor := `<div class="content-threat-actor">
	<div class="content-threat-actor-title">Threat actor</div>
	<div class="content-threat-actor-field">
%s
	</div>
  </div>`
	targets := `<div class="content-targets">
<div class="content-targets-title">Targets</div>
<div class="content-targets-data">
%s
</div>
</div>`
	if len(input.Assets) > 0 {
		var rows string
		row_count := 0
		for i, v := range input.Assets {
			var name string
			if v.Name != nil {
				if v.Name.Common != nil {
					name = *v.Name.Common
				}
				if v.Name.First != nil {
					name = *v.Name.First
					if v.Name.Middle != nil {
						name += *v.Name.Middle
					}
					if v.Name.Last != nil {
						name += *v.Name.Last
					}
				}
			}
			if i == 0 {
				if v.IsThreatActor != nil {
					if *v.IsThreatActor {
						threat_actor = fmt.Sprintf(threat_actor, fmt.Sprintf(`<div class="content-threat-actor-field-icon"></div>
						<div class="content-threat-actor-field-value">%s</div>
						<div class="content-threat-actor-field-cta"></div>`, name))
					} else {
						threat_actor = fmt.Sprintf(threat_actor, fmt.Sprintf(`<div class="content-threat-actor-field-value">%s</div>`, "N/A"))
					}
				} else {
					threat_actor = fmt.Sprintf(threat_actor, fmt.Sprintf(`<div class="content-threat-actor-field-value">%s</div>`, "N/A"))
				}
			}
			meta := fmt.Sprintf(`<div class="content-targets-data-row-meta">
				%s
			  </div>`, "")
			if row_count == 0 {
				row := fmt.Sprintf(`  <div class="content-targets-data-row-first">
				<div class="content-targets-data-row-icon"></div>
				%s
				%s
				<div class="content-targets-data-row-cta">
				</div>
			  </div>`, fmt.Sprintf(`<div class="content-targets-data-row-name">%s</div>`, name), meta)
				rows = rows + `
				` + row
				continue
			}
			row := fmt.Sprintf(`  <div class="content-targets-data-row">
			<div class="content-targets-data-row-icon"></div>
			%s
			%s
			<div class="content-targets-data-row-cta">
			</div>
		  </div>`, fmt.Sprintf(`<div class="content-targets-data-row-name">%s</div>`, name), meta)
			rows = rows + `
			` + row
		}
		targets = fmt.Sprintf(targets, rows)
	} else {
		targets = fmt.Sprintf(targets, "")
		threat_actor = fmt.Sprintf(threat_actor, "")
	}

	txt = strings.Replace(txt, "{{targets}}", targets, 1)
	txt = strings.Replace(txt, "{{threat_actor}}", threat_actor, 1)

	txt = strings.Replace(txt, "{{today_date}}", time.Now().Format("2006-01-02"), 1)

	if input.Date != nil {
		txt = strings.Replace(txt, "{{date}}", input.Date.Format("2006-01-02"), 1)
	}

	if input.Title != nil {
		txt = strings.Replace(txt, "{{title}}", *input.Title, 1)
	}

	if input.Description != nil {
		txt = strings.Replace(txt, "{{summary}}", *input.Description, 1)
	}

	if input.CaseName != nil {
		txt = strings.Replace(txt, "{{case_name}}", *input.CaseName, 1)
	}

	if input.Class != nil {
		txt = strings.Replace(txt, "{{type}}", *input.Class, 1)
	}

	if input.Source != nil {
		txt = strings.Replace(txt, "{{source}}", *input.Source, 1)
	}

	if input.Severity != nil {
		sev_level := "guarded"
		switch *input.Severity {
		case 1:
			sev_level = "guarded"
		case 2:
			sev_level = "low"
		case 3:
			sev_level = "elevated"
		case 4:
			sev_level = "high"
		case 5:
			sev_level = "severe"
		}

		txt = strings.Replace(txt, "{{severity_level}}", sev_level, -1)
	}

	status := "Unreported/Inactive"
	if input.Active != nil {
		if *input.Active {
			status = strings.Replace(status, "Inactive", "Active", -1)
		}
	}

	if input.Reported != nil {
		if *input.Reported {
			status = strings.Replace(status, "Unreported", "Reported", -1)
		}
	}

	txt = strings.Replace(txt, "{{status}}", status, -1)

	return txt
}

func Export(input Incident) error {

	path, err := os.Getwd()
	if err != nil {
		return err
	}

	html = strings.Replace(html, "images/", path+"/source/images/", -1)

	page_1 := Page1(input)
	page_2 := Page2(input)

	html = strings.Replace(html, "{{page_1}}", page_1, 1)
	html = strings.Replace(html, "{{page_2}}", page_2, 1)

	tmp, err := template.New("report").Parse(html)
	if err != nil {
		return err
	}

	os.RemoveAll("/tmp/test.html")
	f, err := os.OpenFile("/tmp/test.html", 0775, fs.FileMode(os.O_CREATE)|fs.FileMode(os.O_RDWR)|fs.FileMode(os.O_TRUNC)|fs.FileMode(os.O_WRONLY))
	if err != nil {
		return errors.New("file open error: " + err.Error())
	}

	err = tmp.Execute(f, nil)
	if err != nil {
		return errors.New("template error: " + err.Error())
	}

	source, err := ioutil.ReadFile("./headless-chromium")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("/tmp/headless-chromium", source, 0777)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath("/tmp/headless-chromium"),
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Headless,
		chromedp.Flag("no-zygote", true),
		chromedp.Flag("single-process", true),
		chromedp.Flag("homedir", "/tmp"),
		chromedp.Flag("data-path", "/tmp/data-path"),
		chromedp.Flag("disk-cache-dir", "/tmp/cache-dir"),
		// chromedp.Flag("remote-debugging-port", "9222"),
		// chromedp.Flag("remote-debugging-address", "0.0.0.0"),
		chromedp.Flag("disable-dev-shm-usage", true),
	}

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	var buf []byte
	err = os.Chmod("/tmp/test.html", 0777)
	if err != nil {
		return err
	}

	err = os.Mkdir("/tmp/images", fs.FileMode(os.O_CREATE)|fs.FileMode(os.O_RDWR)|fs.FileMode(os.O_TRUNC)|fs.FileMode(os.O_WRONLY))
	if err != nil {
		return err
	}

	if err := chromedp.Run(ctx, printToPDF("file:///tmp/test.html", &buf)); err != nil {
		return err
	}

	os.RemoveAll(OUTPUT_PATH)
	if err := ioutil.WriteFile(OUTPUT_PATH, buf, 0777); err != nil {
		return err
	}

	return nil

}

func printToPDF(urlstr string, res *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(urlstr),
		chromedp.ActionFunc(func(ctx context.Context) error {
			buf, _, err := page.PrintToPDF().WithPrintBackground(true).Do(ctx)
			if err != nil {
				return err
			}
			*res = buf
			return nil
		}),
	}
}
