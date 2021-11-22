"""
build a ahocorasic match object per asset.
Take a string representing a text representation of a file.
run it through the matching tree.
if matches make cuts
if cuts make events
"""
import functools
import hashlib
import logging
import pickle
import time
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import chain

from pprint import pprint
from unittest import TestCase
import ahocorasick
import boto3
import pytz
import requests
from pymongo import MongoClient
from typing import List

from chalicelib.lambdaMatcher.MatchEvent import MatchEvent, DocumentData
from chalicelib.lambdaMatcher.MatchObject import MatchObject
from chalicelib.lambdaMatcher.Snippet import Snippet, bayesian_probability
from chalicelib.asset_helpers import asset_to_match_strs
from chalicelib.lambdaMatcher.text_extractor import extract_text_from_html
prod_assets = MongoClient('db4.ia').threatfinder_api.asset

def timeit(method):
    """
    this is a timing decorator to meassure execution time
    :param method:
    :return:
    """
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print('%r  %2.2f ms' % (method.__name__, (te - ts) * 1000))
        return result
    return timed


def match_term_entry(term):
    """
    function that returns a pointer to the key in the term to be matched.
    :param term:
    :return:
    """
    return term[4], {'asset_id': term[0], 'case_id': term[1], 'score': term[2], 'keyword_name': term[3], 'key': term[4]}


def merge_tuples(*t):
    return tuple(j for i in (t) for j in (i if isinstance(i, tuple) else (i,)))


class TextMatcher:
    @timeit
    def __init__(self, db_string, bucket='ia-models', debug=False):
        """
        Tries to read pre trained models from s3 if no models exists rebuilds them from db and stores to s3.

        :param db_string: database connection string for mongodb
        """
        self.db = MongoClient(db_string)
        self.s3cli = boto3.client('s3')

        try:
            self.load_matcher_models_from_s3(bucket)
            if debug: raise RuntimeError('for debug purps')
        except RuntimeError as e:
            logging.warning(e)
            self.asset_matcher_model = self.build_automaton()
            self.threat_actor_matcher = self.build_automaton(threat_actor=True)
            self.update_matcher_models_to_s3(bucket)

    def update_matcher_models_to_s3(self, bucket):
        self.asset_matcher_model = self.build_automaton()
        self.threat_actor_matcher = self.build_automaton(threat_actor=True)
        asset_matcher_pickle = pickle.dumps(self.asset_matcher_model)
        ta_matcher_pickle = pickle.dumps(self.threat_actor_matcher)
        self.s3cli.put_object(Bucket=bucket, Body=asset_matcher_pickle, Key='asset_matcher.pkl')
        self.s3cli.put_object(Bucket=bucket, Body=ta_matcher_pickle, Key='threat_actor_matcher.pkl')

    def load_matcher_models_from_s3(self, bucket):
        # todo: check that the files are newer than 4 hours or yield an exception

            response = self.s3cli.get_object(Bucket=bucket, Key='asset_matcher.pkl')

            old = datetime.utcnow().replace(tzinfo=pytz.utc) - timedelta(hours=4)
            if response['LastModified'] < old:
                raise RuntimeError("Model is old. needs retraining")

            body = response['Body'].read()
            self.asset_matcher_model = pickle.loads(body)

            response = self.s3cli.get_object(Bucket=bucket, Key='threat_actor_matcher.pkl')
            body = response['Body'].read()
            self.threat_actor_matcher = pickle.loads(body)

    def generate_ip_match_keys(self):
        pass


    def generate_match_keys(self, threat_actor=False):
        """
        takes a list of assets and returns a ahocorasick aoutomaton
        :param threat_actor: A boolean if we want threat actor matches or normal matches
        :return:
        """

        asset_collection = self.db.threatfinder_api.asset

        if threat_actor:
            query = {"is_threat_actor": True}
        else:
            query = {'monitored': True}
        assets = asset_collection.find(query)
        for asset in assets:
            asset_id = str(asset.get('_id'))
            case_id = str(asset.get('case_id'))
            score = asset.get('required_score', 0.95)
            # todo implement per keyword type scoring modifiers configurable via a .yaml file
            for res in asset_to_match_strs(asset):
                yield merge_tuples((asset_id, case_id, score), *res)

    def build_automaton(self, threat_actor=False):
        automaton = ahocorasick.Automaton()
        for term_entry in self.generate_match_keys(threat_actor=threat_actor):
            key, new_value = match_term_entry(term_entry)
            try:
                if automaton.exists(key):
                    value = automaton.get(key)
                    value.append(new_value)
                    automaton.add_word(key, value)
                else:
                    automaton.add_word(key, [new_value])
            except TypeError as e:
                logging.exception(e)
                logging.warning("bad key: %s" % str(key))
            # automaton.
        automaton.make_automaton()
        return automaton

    def find_matches(self, text_data: str, threat_actor=False):
        if threat_actor:
            matcher_model = self.threat_actor_matcher
        else:
            matcher_model = self.asset_matcher_model

        for end_index, value in matcher_model.iter(text_data):
            for match in value:
                start_index = end_index - len(match.get('key')) + 1
                m = MatchObject(asset_id=match.get('asset_id'),
                                case_id=match.get('case_id'),
                                asset_score=match.get('score'),
                                start_pos=start_index,
                                end_pos=end_index,
                                matched=match.get('key'),
                                keyword_name=match.get('keyword_name'))
                if m.validate_match(text_data):
                    yield m


    def matches_to_snippets(self, matches: List[MatchObject], text_data: str) -> List[Snippet]:
        """
        Takes a list of MatchObjects and returns the corresponging text snippets or (cuts)
        """
        snippets = []
        matched_keyword_names = []
        #first make a new snippet from
        matches.sort()
        snippet = Snippet.from_match(matches.pop(0), text_data)

        for match in matches:
            if match.keyword_name in matched_keyword_names:
                continue

            if snippet.intersects(match):
                # if match overlaps and are a type not matched yet. add it to the match
                snippet.append_match(match, text_data)

            else:
                # add the snippet and make a new one, this is where the snippets are broken up. question should we
                # restart matched keywords
                snippets.append(snippet)
                snippet = Snippet.from_match(match, text_data)
            matched_keyword_names.append(match.keyword_name)
        snippets.append(snippet)
        return snippets


    def sort_matches(self, matches):
        """
        Takes all matches for a document sorts them by matched asset and returns a dict of assset_id
        :param matches:
        :return:
        """
        sorted = defaultdict(list)
        for match in matches:
            sorted[match.asset_id].append(match)
        return sorted

    def score_asset_matches(self, matches: List[MatchObject]):
        """
        simplified scoring algo that
        :param matches:
        :return:
        """

        #scores = [match.score for match in matches]
        prob = bayesian_probability(matches)
        return prob

    @functools.lru_cache(32)
    def find_threat_actor_matches(self, text_data, url):
        """
        If we have a document matching a protected asset we also want to check which threat actors it potentially match.
        This function finds and returns the snippets or cuts matching threat actors for the same document
        :return: [Snippet]
        """
        ta_matches=[]
        text_matches = self.find_matches(text_data, threat_actor=True)
        url_matches = self.find_matches(url, threat_actor=True)

        all_matches = chain(text_matches, url_matches)
        sorted_matches = self.sort_matches(all_matches)

        for asset_id, matches in sorted_matches.items():

            required_score = matches[0].asset_score
            matched_asset_score = self.score_asset_matches(matches)
            if matched_asset_score >= required_score:
                snippets = self.matches_to_snippets(matches, text_data)
                scored_snippets = [snippet for snippet in snippets if snippet.score() > required_score]
                if len(scored_snippets):
                    print('[potential TA match: %s] score: %s' % (asset_id, matched_asset_score))
                    ta_matches += scored_snippets
        return ta_matches

    def match_ips_and_cidr(self, text):
        pass
        #todo: extract all ips and match against the ipaddress module

    @timeit
    def match(self, url: str, text_data, document_data: DocumentData):
        asset_matches = self.sort_matches(self.find_matches(text_data))
        for asset_id, matches in asset_matches.items():
            required_score = matches[0].asset_score
            case_id = matches[0].case_id
            matched_asset_score = self.score_asset_matches(matches)
            if matched_asset_score > required_score:
            #first we make a pre score of the entire document
                snippets = self.matches_to_snippets(matches, text_data)
                #then we score each cut individially to assure that the matches are clustered
                snippets = [snippet for snippet in snippets if snippet.score() > required_score]
                if len(snippets) > 0:
                    threat_actor_matches = self.find_threat_actor_matches(text_data, url)

                    content_hash = hashlib.md5(text_data.encode('utf-8')).hexdigest()
                    yield MatchEvent(case_id=case_id,
                                     asset_id=asset_id,
                                     url=url,
                                     probability=matched_asset_score,
                                     cuts=snippets,
                                     threat_actor_matches= threat_actor_matches,
                                     content_hash=content_hash,
                                     document_data=document_data,
                                     content_type=document_data.content_type
                                     )

# t = TextMatcher()
# t.match("this text do contain the name thomas olofsson and the email: thomas@intelliagg.com and should therefore match "
#         "at least one asset."
#         "returns a base score of the matched string calculated based on the uniqunes of the string and the length of "
#         "the string.", "https://www.intelliagg.com/test_thomas.html")

class TestEvent(TestCase):
    def testSave(self):
        pass

class TestMatcher(TestCase):
    asset_collection = MongoClient('dev-db.ia').threatfinder_api.asset
    def setUp(self) -> None:
        self.tests_urls = ['https://gofyeo.com',
                           'https://howden.com']
        # self.m = TextMatcher(prod=False)

    def get_test_data(self, url):
        resp = requests.get(url)
        return resp.content


    def testMatcherMatch(self):
        t = TextMatcher('dev-db.ia')
        for url in self.tests_urls:
            html = self.get_test_data(url)
            metadata, text = extract_text_from_html(html)
            eventsGenerator = t.match(url, text, metadata)
            matches = list(eventsGenerator)
            self.assertGreaterEqual(len(matches),1)
            for match in matches:
                pprint(match)

    def test_threat_actor(self):
        t = TextMatcher('dev-db.ia', debug=True)
        text = "thomas olofsson [thomas@intelliagg.com] is a bad bad person and shoud be doxed on the interwebz."
        url = 'http://pastebin.com/twegfasgag/'
        meta = DocumentData(title= "test",
                            content_type= 'text/plain',
                            content_length=len(text),
                            content_encoding= None,
                            content_language= 'en')
        for match_event in t.match(url, text, meta):
            pprint(match_event.to_dict())


    def test_generate_match_keys(self):
        t = TextMatcher('dev-db.ia')
        matchKeys = t.generate_match_keys()
        matchKey = next(matchKeys)
        print(matchKey)