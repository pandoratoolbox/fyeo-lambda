import logging
import time
from unittest import TestCase

import boto3
import requests
from pymongo import MongoClient

from chalicelib.lambdaMatcher import text_extractor
from chalicelib.lambdaMatcher.LegacyEvent import LegacyEvent
from chalicelib.lambdaMatcher.text_matcher import TextMatcher
from chalicelib.urlCache import UrlCache


class DocumentMatcher:
    def __init__(self, sqs_queue, db_host, database, collection, debug=False):
        self.processed = 0
        self.queue = sqs_queue
        self.db = MongoClient(db_host)[database]
        self.collection = collection
        self.textMatcher = TextMatcher(db_host, debug=debug)
        self.url_cache = UrlCache(agent='matcher')
        self.s3 = boto3.client('s3')

    def match_s3_doc(self, link, bucket='downloads.intelliagg'):
        res = link
        try:
            t = time.time()
            print("started matching %s" % link['url'])
            document_data, text_data = text_extractor.extract_text_from_s3(link['url'], bucket=bucket)
            res['processed'] = len(text_data)
            res['content-type'] = document_data.content_type

            for event in self.textMatcher.match(link['url'], text_data, document_data=document_data):
                print('created event for: %s matching asset %s' % (event.url, event.asset_id))
                # for snippet in event.cuts:
                #     for match in snippet.matches:
                #         print("-> Matching : %s" % match)
                #event.fix_base_offset()
                event.to_db(self.db, 'tf', 'events_v2')
                le = LegacyEvent.fromEvent(event)
                #le.fix_base_offset()
                le.to_db(self.db, 'tf', 'legacy_events')
            res['status'] = 'success'
        except Exception as e:
            print('failed processing for link %s')
            logging.exception(e)
            res['status'] = 'error'
            res['message'] = str(e)
        self.url_cache.check_and_update(link)
        print("[Matcher] took %s for %s" % (time.time() - t, link['url']))
        return res

    def match_from_lambda(self, link, cache=True):

        if cache and self.url_cache.exists(link):
            link['status'] = 'cached'
            yield link
        else:
            yield self.match_s3_doc(link)


    def readFromS3(self, link):
        try:
            obj = self.s3.get_object(Bucket="downloads.intelliagg", Key=link.get('url'))
            contentType = obj.get('ContentType')
            stream = obj.get("Body")
            data = stream.read()
        except self.s3.exceptions.NoSuchKey as e:
            print('could not find key: %s' % link.get('url'))
            data = ""
            contentType = "text/html"
        except Exception as e:
            logging.exception(e)
            data = ""
            contentType = "text/html"

        return data, contentType

    def match_url(self, url):
        """
        This function downloads and matches from a url. it is mostly for testing purposes to be able to
        test the matcher without having to download via the normal stack
        :return:
        """
        resp = requests.get(url)
        data = resp.content
        meta_data, text = text_extractor.extract_text_from_html(data)
        for event in self.textMatcher.match(url, text, meta_data):
            event.to_db(self.db, 'tf', 'legacy-events')
            le = LegacyEvent.fromEvent(event)
            inserted_id = le.to_db(self.db, 'tf', 'legacy-events')
            if inserted_id:
                print('created event for: %s matching asset %s event_id:%s' % (event.url, event.asset_id, inserted_id))


class test_matcher(TestCase):
    def setUp(self):
        sqs = boto3.resource('sqs')
        sqs_queue = sqs.get_queue_by_name(QueueName='lambda-matcher')
        self.matcher = DocumentMatcher(sqs_queue=sqs_queue,
                                       db_host='dev-db.ia',
                                       database='intelliagg',
                                       collection='test-events',
                                       debug=True)

    def test_url(self):
        test_urls = ['https://www.hyperiongrp.com/key-people', #yields to many events
                     'https://en.wikipedia.org/wiki/Bitcoin', #wikipedia yielded super long cuts. Fixed
                     'https://www.benzinga.com/pressreleases/16/08/p8298965/intelliagg-announces-acquisition-of-darksum',
                     ]
        for url in test_urls:
            self.matcher.match_url(url)

    def test_text_file(self):
        pass

    def test_cache(self):
        self.matcher.debug = False #so we actually use the cache


    def test_s3(self):
        links = [
            # {"url": "https://www.survivalcatsupply.com/pages/affiliate-disclosure"},
            # {'url': 'https://www.ratsit.se/lonekollen/kop/fNEZ_EkBYzZ17ezlO4xE9-xbkrowbkuM54LaJOtOLvc'},
            {"url": 'http://www.authorstream.com/Presentation/bucarobrothersautoca-4395500-best-auto-repair-service-bucaro-brothers-care/'}]
        for link in links:
            res = self.matcher.match_s3_doc(link)
            print(res)