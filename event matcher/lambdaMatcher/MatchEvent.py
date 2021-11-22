import dataclasses
from dataclasses import dataclass

from datetime import datetime
from typing import Union, Dict, List
from unittest import TestCase
from urllib.parse import urlparse

import yaml
from bson import ObjectId
from pymongo import MongoClient

from chalicelib.lambdaMatcher.MatchObject import MatchObject
from chalicelib.lambdaMatcher.Snippet import Snippet
from chalicelib.helpers import content_hash

from pathlib import Path
path = Path(__file__).parent / "social_media_sites.yaml"

with open(path) as file:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
    social_media = yaml.load(file, Loader=yaml.FullLoader)

@dataclass
class DocumentData:
    title: str
    content_type: str
    content_length: int
    content_encoding: Union[str, None]
    content_language: str

@dataclass
class MatchedAsset:
    _id: str
    asset_type: str
    name: Dict[str, str]
    is_threat_actor: bool
    emails: [Dict[str,str]]
    case_id: str
    social_media: List[Dict[str, str]]
    phones: [Dict[str, str]]
    urls: [Dict[str, str]]
    organization: Dict[str, str]
    location: Dict[str, str]

    @classmethod
    def from_db(cls, id, db_con, db, collection):
        asset = db_con[db][collection].find_one({"_id": ObjectId(id)})
        return cls(
            id,
            asset.get('asset_type'),
            asset.get('name'),
            asset.get('is_threat_actor'),
            asset.get('emails'),
            asset.get('case_id'),
            asset.get('social_media'),
            asset.get('phones'),
            asset.get('urls'),
            asset.get('organization'),
            asset.get('location')
        )


@dataclass
class MatchEvent:
    """
    An event representing a matched mention on of a keyword.
    """
    case_id: str
    asset_id: str
    url: str
    content_hash: str
    content_type: str
    probability: float
    document_data: DocumentData
    cuts: [Snippet]
    threat_actor_matches: [Snippet]
    site: str = dataclasses.field(init=False)
    title: str = ""
    source_network: str = ""
    hash: str = ""
    matched_asset: Union[None, MatchedAsset] = None

    def __post_init__(self):
        self.site: str = urlparse(self.url).netloc
        self.source_network = self.set_source_network()
        self.hash = self.to_hash()
        self.time = datetime.now()
        self.title = self.document_data.title
        for snippet in self.cuts:
            snippet.fix_base_offset()

    @classmethod
    def from_snippets(cls, case_id, asset_id, url, content_hash, probability, snippets: [Snippet]):
        return cls(case_id, asset_id, url, content_hash, probability, snippets)

    def to_dict(self):
        return dataclasses.asdict(self)

    def to_hash(self):
        string = str(self.to_dict())
        return content_hash(string)

    def set_source_network(self):
        netloc = urlparse(self.url).netloc
        if netloc.endswith('onion') or 'dumps.intelliagg' in netloc :
            return 'dark-net'
        elif netloc in social_media:
            return 'social-media'
        else:
            return 'clear-net'

    def to_db(self, db_conn, db, collection) -> Union[None, ObjectId]:
        try:
            self.matched_asset = MatchedAsset.from_db(self.asset_id, db_conn, 'threatfinder_api', 'asset')
        except AttributeError:
            pass

        if not db_conn[db][collection].find_one({'hash': self.hash}):
            res = db_conn[db][collection].insert_one(self.to_dict())
            if res:
                return res.inserted_id
#
# def match_events_from_db(db, query):
#     """
#
#     :param db:
#     :return:
#     """
#     for event in db.events.find(query).sort([('_id',-1)]):
#         try:
#             matchEvent = from_dict(data_class=MatchEvent, data=event, )
#             yield matchEvent
#         except WrongTypeError as e:
#             pass


class TestEvent(TestCase):
    # def testFromDb(self):
    #     db = MongoClient('dev-db.ia').intelliagg
    #     for event in match_events_from_db(db, {}):
    #
    #         print (event)

    def test_asset_from_db(self):
        db = MongoClient('dev-db.ia')
        asset = MatchedAsset.from_db("5a65cb501d41c82640a1e62b", db, 'threatfinder_api', 'asset')
        print(asset)

    def testSave(self):
        db = MongoClient('dev-db.ia')
        content = 'this text do contain the name thomas olofsson and the email: thomas@intelliagg.com and should ' \
                  'therefore match at least one asset.returns a base score of the matched string calculated based ' \
                  'on the uniqunes of the string and the leng'

        s = Snippet(start_pos=100, end_pos=231,
                    cut='this text do contain the name thomas olofsson and the email: thomas@intelliagg.com and should '
                        'therefore match at least one asset.returns a base score of the matched string calculated based '
                        'on the uniqunes of the string and the leng',
                    matches=[MatchObject(asset_id='5a6b0d745aa59b123d8dcb32', case_id='5a6b0d745aa59b123d8dcb32',
                                         matched='intelliagg.com',
                                         asset_score="85",
                                         keyword_name='organization.name', start_pos=68, end_pos=81)], offset=150)

        e = MatchEvent(asset_id='5a65cb501d41c82640a1e62b',
                       url="http://intelliagg.com/test.html",
                       content_hash=content_hash(content),
                       case_id='test',
                       cuts=[s],
                       probability=.9,
                       document_data=DocumentData('title', 'text/html', len(content), 'utf-8', 'en'),
                       content_type= '',
                       threat_actor_matches=[]
                       )

        res = e.to_db(db, 'intelliagg', 'events')
        print(res)
