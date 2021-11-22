import logging
import mimetypes
import tempfile
from urllib.parse import urlparse
import boto3
import langdetect
import textract
from bs4 import BeautifulSoup
from langdetect import DetectorFactory
import PyPDF2
from langdetect.lang_detect_exception import LangDetectException

DetectorFactory.seed = 0

from chalicelib.lambdaMatcher.MatchEvent import DocumentData

s3 = boto3.client('s3')
bucket = 'downloads.intelliagg'


def detect_language(text: str, content_type:str) -> str:
    if content_type == "application/json":
        return 'en'
    else:
        try:
            return langdetect.detect(text)
        except (LangDetectException, TypeError):
            return "en"

def detect_filetype(url: str) -> str:
    file = urlparse(url).path
    if not file or file.endswith('.com'):
        mime = 'text/html'
    else:
        mime = mimetypes.guess_type(url)[0]
    if not mime:
        file = urlparse(url).path
        mime = mimetypes.guess_type(file)[0]

    # if not mime and data:
    #     mime = magic.from_buffer(data)
    if not mime:
        return ".htm"
    else:
        return mimetypes.guess_extension(mime)


def extract_text_from_html(html_data):
    soup = BeautifulSoup(html_data, features="html5lib")

    # kill all script and style elements
    for script in soup(["script", "style"]):
        script.extract()  # rip it out

    # get text
    try:
        text = soup.body.get_text()
        title = str(soup.title.string)
    except Exception as e:
        text = soup.get_text()
        title = 'NA'

    # break into lines and remove leading and trailing space on each
    lines = (line.strip() for line in text.splitlines())
    # break multi-headlines into a line each
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    # drop blank lines
    text = '\n'.join(chunk for chunk in chunks if chunk) + "\n"

    metadata = DocumentData(title, 'text/html', len(html_data), 'utf-8', detect_language(text, 'text/html'))
    return metadata, text.lower()


def extract_text_from_s3(key, bucket="downloads.intelliagg"):
    obj = s3.head_object(Bucket=bucket, Key=key)
    contentType = obj.get('ContentType').split(';')[0]
    contentLength = obj.get('ContentLength')
    encoding = obj.get('contentEncoding', 'utf-8')

    doc_metadata = DocumentData(title=str(key),
                                content_type=contentType,
                                content_length=int(contentLength),
                                content_language='NA',
                                content_encoding=encoding)

    if contentType in ['text/html', 'application/json']:
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            raw_data = obj.get('Body').read().decode(encoding)
        except UnicodeDecodeError:
            logging.warning('[text_extractor] error decoding document %s encoding: %s' % (key, encoding))

        if contentType == 'application/json':
            doc_metadata.content_language = 'en'
            return doc_metadata, raw_data
        if contentType == 'text/html':
            meta, text = extract_text_from_html(raw_data)
            doc_metadata.content_language = detect_language(text, contentType)
            return doc_metadata, text

    elif contentType == 'application/pdf':

        doc = PyPDF2.PdfFileReader(obj.get('Body'))
        numPags = doc.getNumPages()
        textoComplete = ""
        for i in range(numPags):
            textoComplete += doc.getPage(i).extractText()
        return doc_metadata, textoComplete


    else:
        ext = detect_filetype(key)
        with tempfile.NamedTemporaryFile(suffix=ext, dir='/tmp') as temp_f:
            s3.download_fileobj('downloads.intelliagg', key, temp_f)
            temp_f.seek(0)
            text = textract.process(temp_f.name)
            doc_metadata.content_language = detect_language(text, contentType)
            return doc_metadata, text.decode('utf-8')
