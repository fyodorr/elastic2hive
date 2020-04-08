import ssl
import json
import uuid
import requests
import time
from elasticsearch.connection import create_ssl_context
from elasticsearch import Elasticsearch
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HIVE_URL = ""
HIVE_APIKEY = ""
ES_HOST = ""
ES_PORT = 9200
ES_USERNAME = ""
ES_PASSWORD = ""

context = create_ssl_context(cafile="ca.crt")
#context.check_hostname = True
#context.verify_mode = ssl.CERT_NONE
es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT}], http_auth=(ES_USERNAME, ES_PASSWORD), scheme="https", ssl_context=context)

# Load the field_mapping file to map Elasticsearch fields to Hive Artifacts

class CustomJsonEncoder(json.JSONEncoder):
    def default(self,o):
        if isinstance(o, JSONSerializable):
            return o.__dict__
        else:
            return json.JSONEncoder.default(self,o)

class JSONSerializable(object):
    def jsonify(self):
        return json.dumps(self, sort_keys=True, indent=4, cls=CustomJsonEncoder)

    def attr(self, attributes, name, default, error=None):
        is_required = error is not None

        if is_required and name not in attributes:
            raise_with_traceback(ValueError(error))
        else:
            return attributes.get(name, default)

class Artifact(JSONSerializable):
    def __init__(self, **attributes):
        if attributes.get('json', False):
            attributes = attributes['json']

        self.dataType = attributes.get('dataType', None)
        self.message = attributes.get('message', None)
        self.tlp = attributes.get('tlp', 2)
        self.tags = attributes.get('tags', [])
        self.data = attributes.get('data', None)


class Alert(JSONSerializable):
    def __init__(self, **attributes):
        if attributes.get('json', False):
            attributes = attributes['json']

        self.tlp = attributes.get('tlp', 2)
        self.severity = attributes.get('severity', 2)
        self.date = attributes.get('date', int(time.time()) * 1000)
        self.tags = attributes.get('tags', [])
        self.caseTemplate = attributes.get('caseTemplate', None)

        self.title = self.attr(attributes, 'title',
                               None, 'Missing alert title')
        self.type = self.attr(attributes, 'type', None, 'Missing alert type')
        self.source = self.attr(attributes, 'source',
                                None, 'Missing alert source')
        self.sourceRef = self.attr(
            attributes, 'sourceRef', None, 'Missing alert reference')
        self.description = self.attr(
            attributes, 'description', None, 'Missing alert description')
        self.customFields = self.attr(attributes, 'customFields', {})

        artifacts = attributes.get('artifacts', [])
        self.artifacts = []
        for artifact in artifacts:
            if type(artifact) == Artifact:
                self.artifacts.append(artifact)
            else:
                self.artifacts.append(Artifact(json=artifact))


with open('field_mappings.json') as f:
    field_mapping = json.load(f)

def get_nested(message, *args):
    if args and message:
        element = args[0]
        if element:
            value = message.get(element)
            return value if len(args) == 1 else get_nested(value, *args[1:])

def create_alert(alert):

    headers = {
        'Authorization': 'Bearer {}'.format(HIVE_APIKEY),
        'Content-Type': 'application/json'
    }
    
    response = requests.post(HIVE_URL+'/api/alert', headers=headers, data=alert)
    if response.status_code == 200 | 201:
        print('[!] Created alarm \'{}\' with reference ID {}'.format(json.loads(alert)['title'], json.loads(alert)['sourceRef']))
        return True
    else:
        print('[!] Failed to create alarm: {}'.format(json.loads(response.content)['message']))
        return False

def create_mitre_tags(threats):
    tags = []

    if len(threats) > 0:
        for threat in threats:
            tags += ['%s (%s)' % (threat['tactic']['id'], threat['tactic']['name'])]
        
            for technique in threat['technique']:
                tags += ['%s (%s)' % (technique['id'], technique['name'])]

    return tags

if __name__ == "__main__":
    while(1):
        print('[-] Querying Elasticsearch...')
        res = es.search(index='.siem-signals-*', body={'query': {'range': {"@timestamp": {"gt": "now-5m"}}}})
        
        print('[-] Found {} signals.'.format(len(res['hits']['hits'])))
        for doc in res['hits']['hits']:

            source = doc['_source']  

            # Build a clean description
            description = "%s\n\n**False Positives**:\n%s\n\n**References**:\n%s\n\n**Query**: `%s`" % (
                source['signal']['rule']['description'],
                "\n".join(["- {}".format(fp) for fp in source['signal']['rule']['false_positives']]),
                "\n".join(["- ({})[{}]".format(ref, ref) for ref in source['signal']['rule']['references']]),
                source['signal']['rule']['query']
            )

            # Build the base alert
            alert = Alert(title=source['signal']['rule']['name'],
                description=description,
                tlp=2,
                type='external',
                source='elastic-signals',
                sourceRef=source['signal']['ancestors'][0]['id'],
                #sourceRef=str(uuid.uuid4())[0:6],
                artifacts=[],
                tags=[])

            # Gather all the tags, turn mitre tech/tactics into tags
            alert.tags += create_mitre_tags(source['signal']['rule']['threat'])
            alert.tags += source['signal']['rule']['tags']

            # Extract observables via field_mappings
            for observable in field_mapping['fields']:

                value = get_nested(source,*observable['field'].split('.'))
                if isinstance(value, list):
                    value = ' '.join(value)
                if value:
                    alert.artifacts += [Artifact(data=value, dataType=observable['dataType'], tlp=observable['tlp'])]
                else:
                    pass
            
            print('[-] Sending alert \'{}\' to TheHive'.format(source['signal']['rule']['name']))
            create_alert(alert.jsonify())
        time.sleep(30)
    

