import dataclasses
import urllib
from datetime import datetime
from dataclasses import dataclass, field
from pprint import pprint
from unittest import TestCase
from typing import List, Union
from urllib.parse import urlparse

import yaml
from bson import ObjectId
from pymongo import MongoClient

from chalicelib.lambdaMatcher.MatchEvent import MatchEvent, DocumentData
from chalicelib.lambdaMatcher.MatchObject import MatchObject
from chalicelib.lambdaMatcher.Snippet import Snippet
from chalicelib.helpers import content_hash

source_network_table = {
    "dark-net": "darknet",
    "clear-net": "public",
    "social-media": "social"
}

@dataclass
class LegacyCut:
    cut: str
    matches: field(default_factory=list, init=False)
    line_hash: str = ""
    type: str = "m"
    len: int = 0
    translated: str = ""
    max_tag: int = 0
    hashVersion: int = 4
    tags: list = field(default_factory=dict)


    def __post_init__(self):
        self.line_hash = content_hash(self.cut)
        self.len = len(self.cut)
        self.translated = self.cut

    def to_dict(self):
        return dataclasses.asdict(self)

@dataclass
class LegacyMatch:
    asset_id: str
    is_threat_actor: bool
    searchTerm: str
    standalone: bool = True
    required: bool = True
    entity: dict = field(default_factory=dict)
    info: str = ""
    expression: str = ""

@dataclass
class LegacyEvent:
    caseId: str
    asset_id: str
    url: str
    title: str
    contentHash: str
    sourceContentType: str
    confidence_score: float
    cuts: List[LegacyCut]
    time: datetime
    language: str
    sourceNetwork: str
    version: int = 4
    threatLevel: int = 1
    isAutoClassified: bool = True
    isManClassified: bool = True
    isTranslated: bool = True

    languages: List[str] = field(default_factory=list)
    translated: bool = True
    agent: str = "lambda_matcher"
    hash: str = ''

    def __post_init__(self):
        self.hash = content_hash(str(self.to_dict()))
        self.sourceType = self.sourceContentType
        self.time = datetime.now()
        self.languages.append(self.language)
        try:
            self.sourceNetwork = source_network_table[self.sourceNetwork]
        except IndexError:
            pass

    @classmethod
    def translateSource(cls, souceNetwork):
        pass

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def fromEvent(cls, event: MatchEvent):
        """
        Creates a legacy event from a new event
        :type event: object
        """

        legacy_cuts = []
        for cut in event.cuts:
            legacy_cuts.append(LegacyCut(cut=cut.cut,  matches=cut.matches))

        return cls(contentHash=event.content_hash,
                   sourceContentType=event.document_data.content_type,
                   caseId=event.case_id,
                   asset_id=event.asset_id,
                   url=event.url,
                   title=event.document_data.title,
                   cuts=legacy_cuts,
                   confidence_score=event.probability,
                   time=event.time,
                   language=event.document_data.content_language,
                   sourceNetwork=event.source_network
                   )

    def to_db(self, db_conn, db, collection) -> Union[None, ObjectId]:
        if not db_conn[db][collection].find_one({'hash': self.hash}):
            res = db_conn[db][collection].insert_one(self.to_dict())
            if res:
                return res.inserted_id

class Test_LegacyEvent(TestCase):
    def test_to_db(self):
            content = 'this text do contain the name thomas olofsson and the email: thomas@intelliagg.com and should ' \
                      'therefore match at least one asset.returns a base score of the matched string calculated based ' \
                      'on the uniqunes of the string and the leng'

            s = Snippet(start_pos=0, end_pos=231,
                        cut='this text do contain the name thomas olofsson and the email: thomas@intelliagg.com and should '
                            'therefore match at least one asset.returns a base score of the matched string calculated based '
                            'on the uniqunes of the string and the leng',
                        matches=[MatchObject(asset_id='5a6b0d745aa59b123d8dcb32', case_id='5a6b0d745aa59b123d8dcb32',
                                             matched='intelliagg.com',
                                             asset_score='.5',
                                             keyword_name='organization.name', start_pos=68, end_pos=81)], offset=150)

            e = MatchEvent(case_id="50a66ac6560e4012040fbfc5",
                           asset_id="5a6228bf1d41c8a4e8a91c65",
                           url="http://intelliagg.com/test.html",
                           content_hash=content_hash(content),
                           content_type='text/html',
                           cuts=[s],
                           probability=.9,
                           document_data= DocumentData(title='test',
                                                      content_type="text/html",
                                                      content_language='en',
                                                      content_encoding='utf-8',
                                                      content_length=234),
                           threat_actor_matches = []
                           )


            l = LegacyEvent.fromEvent(e)
            db = MongoClient('db4.ia')
            res = l.to_db(db, 'tf', 'legacy_events')
            print(res)
            pprint (l.to_dict())