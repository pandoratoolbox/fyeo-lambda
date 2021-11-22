import json
import logging
import os
import re
from datetime import datetime, timedelta
import copy
from bson import ObjectId
from pymongo import MongoClient

mongo = MongoClient()


def classify_event(event, threat_level, rule):
    action = {"action": "auto-classed",
              "user": "rules-engine",
              "date": datetime.now(),
              "threatLevel": threat_level,
              "rule": rule}

    res = mongo.tf.events.update_one({"_id": event['_id']},
                                     {"$set": {"isManClassified": True, "isAutoClassified": True,
                                               'threat_level': threat_level},
                                      "$push": {'history': action}})


def get_name_for_threat_actor(threat_actor_info):
    return threat_actor_info.get('name', "unknown")

def getDumpSource(event):
    url = event.get('url')
    try:
        source = url.split("/")[3]
    except Exception:
        source = 'NA'
    return source


class RulesEngine(object):
    def __init__(self, debug=False, prod=False, test=False):
        global mongo
        if prod:
            mongo = MongoClient('db4.ia')
        self.mongo = mongo.tf
        self.assets = mongo.threatfinder_api.asset
        self.base_query = {
            'time': {"$gt": datetime.now() - timedelta(days=7)},
            'isManClassified': False,
        }

        self.test = test

        with open('%s/rules.json' % os.path.dirname(os.path.realpath(__file__))) as f:
            self.rules = json.load(f)

        self.debug = debug
        self.incident_types = [incident_type for incident_type in self.mongo.incident_types.find()]

    def setRules(self, rules):
        """
        this is mostly used by unit test to test rule functionality
        :param rules:
        :return:
        """
        self.rules = rules

    def appylRules(self):

        for rule in self.rules:
            q = copy.copy(self.base_query)

            for key, value in rule.get('filter', {}).items():
                q[key] = value

            if rule.get('action') == 'update':
                self.update_events(q, rule)
                continue

            if rule.get('action') == 'incident':
                rule_params = rule.get('params', {})
                events = self.mongo.events.find(q)
                print ("[%s]: %s" %(rule.get('name'), events.count()))
                threat_level = rule_params.get('threat_level', 3)
                for event in events:
                    if ObjectId(event['asset_id']) in event.get('threat_actors_list', []):
                        classify_event(event, threat_level=3, rule=rule.get('name'))
                        continue

                    threat_actor = rule_params.get('threat_actor', False)
                    incident_type = rule_params.get('incident_type')
                    dump = rule_params.get('dump', False)

                    classify_event(event, threat_level, rule=rule.get('name'))
                    self.createIncident(event, incident_type, threat_actor=threat_actor, dump=dump)

        self.auto_close_known_whois()

    def update_events(self, q, rule):
        update = rule.get('update', {})
        rule_name = rule.get('name', '?')
        res = self.mongo.events.update_many(q, {"$set": update})
        res = self.mongo.events.update_many(q,
                                            {"$push":
                                                {'history':
                                                    {
                                                        "action": "auto-classed",
                                                        "user": "rules-engine",
                                                        "date": datetime.now(),
                                                        "rule": rule_name
                                                    }
                                                }
                                            })

    def add_to_incident(self, incident_id, event):
        """
        :param incident_id:
        :param event:
        :return:
        """
        try:
            res = self.mongo.incidents.update_one({'_id': ObjectId(incident_id)},
                                                  {'$addToSet': {'events': str(event.get('_id')),
                                                                 'targets': event.get('asset_name')}})
        except Exception as e:
            logging.exception(e)
            return
        self.mongo.events.update_one({'_id': event['_id']},
                                     {'$set': {'incident': str(incident_id), 'isManClassified': True}})

        return res

    def get_threat_actor_info(self, _id):

        ta = self.assets.find_one({'_id': _id, 'is_threat_actor': True})
        if ta == None:
            return False
        if ta['asset_type'] in ['domain', 'organisation']:
            name = ta.get('name', {}).get('common')
        elif ta['asset_type'] == 'person':
            name = "%s %s" % (ta.get('name').get('last'), ta.get('name').get('first'))
        else:
            name = 'unkown'

        return {'name': name, 'description': ta.get('description', '')}

    def get_source_cert(self, event):
        try:
            source = event.get('url').split('/')[4]
            return source
        except IndexError:
            cut_txt = event.get('cuts')[0].get('cut')
            sources = re.findall("\'[0-9a-z\.]*\.[a-z]*\'", cut_txt)
            for source in sources:
                source.replace(r"\\'", "")
                source.replace(r"'", "")
                print(source)
                if source != event.get('cuts')[0].get('matched').get('searchTerm'):
                    return source

    def createIncident(self, event, incident_type, threat_actor=False, dump=False):
        """
        this function creates an incident bases
        :param event:
        :param incident_type:
        :return:
        """
        if dump:
            source = getDumpSource(event)

        elif incident_type in ['similar_domain', 'existing_similar_domain']:
            try:
                source = event.get('url').split('/')[4]
            except IndexError:
                source = event.get('url').split('/')[3]
        elif incident_type == 'new_cert_discovered' or incident_type == "new_multi_cert":
            source = self.get_source_cert(event)
        else:
            source = event.get('site')

        incident_template = next(item for item in self.incident_types if item["class"] == incident_type)

        if threat_actor:
            threat_actor_info = self.get_threat_actor_info(event.get('threat_actors_list')[0])
            threat_actor_name = get_name_for_threat_actor(threat_actor_info)
            title = incident_template.get('title') % (event.get('asset_name', "asset"), source, threat_actor_name)
            threat_actor_id = str(event.get('threat_actors_list')[0])

        else:
            threat_actor = ''
            threat_actor_id = ''
            title = incident_template.get('title') % (event.get('asset_name', "asset"), source)

        inc_data = {
            'title': title,
            "case_Name": '',
            "class": incident_type,
            'type': incident_type,
            "classifiedBy": 'intelliagg.com',
            "parentId": event.get('caseId'),
            "asset_id": event.get('asset_id'),
            "classifiedDate": event['time'],
            "description": incident_template.get('description'),
            "recommendations": incident_template.get('recommendation'),
            "threat_actor": threat_actor,
            "threat_actor_id": threat_actor_id,
            "source": "%s" % source,
            "date": event.get('time'),
            "severity": int(incident_template.get('severity')),
            "targets": [event.get('asset_name')],
            "agent": 'rules_engine',
            "active": True,
            "reported": False
        }
        existing_incident = self.mongo.incidents.find_one(
            {'parentId': inc_data['parentId'], 'source': inc_data['source'], 'title': {"$regex": inc_data['title'][:15]}})
        if existing_incident:
            _id = existing_incident['_id']
        else:
            logging.info('creating incident: %s [%s]' % (inc_data['title'], inc_data['date']))
            _id = self.mongo.incidents.insert_one(inc_data).inserted_id

        self.add_to_incident(_id, event)

    def getSourceForDumpsEvent(self, event):
        pass

    def auto_close_known_whois(self):
        incidents = mongo.tf.incidents.find({'type': "similar_domain", 'active': True})

        for incident in incidents:
            source = incident.get('source', '')
            target = incident.get('targets')[0]
            if source.endswith(target):
                mongo.tf.incidents.update_one({"_id": incident.get('_id')},
                                              {"$set": {'active': False,
                                                        'recommendations': 'closed since it is a known subdomain',
                                                        'closed_date': datetime.now()
                                                        }})


if __name__ == "__main__":
    reg = RulesEngine(debug=True, prod=True, test=True)
    reg.appylRules()

