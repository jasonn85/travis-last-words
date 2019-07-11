import json
from random import choice
import os
import botocore.vendored.requests as requests  # I found you, requests
from urllib.parse import parse_qs

from typing import Optional

import logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

travis_config_url = 'https://api.travis-ci.org/config'

# Which states do we consider failures out of:
# :created, :received, :started, :passed, :failed, :errored, :canceled
failure_states = ['failed', 'errored']

repository_owners = os.environ.get('GITHUB_OWNERS').split(' ')

def lambda_handler(event, context):
    logger.debug('Input: ' + json.dumps(event))
    
    # These other methods of decoding should be removed at some point.
    if event.get('headers', {}).get('Content-Type', '') == 'application/x-www-form-urlencoded':
        # This comes from Travis
        payload = parse_qs(event['body'])['payload']
        body = json.loads(payload[0])
    elif isinstance(event['body'], dict):
        body = event['body']
    else:
        body = json.loads(event['body'])
        
    logger.debug('Body of type %s is: %s' % (str(body.__class__), str(body)))
    
    if 'ALLOW_UNSIGNED' not in os.environ:
        from OpenSSL.crypto import verify, load_publickey, FILETYPE_PEM, X509
        from OpenSSL.crypto import Error as SignatureError
        
        signature = event['headers']['Signature']
        logger.debug('Signature is ' + signature)
        
        response = requests.get(travis_config_url)
        public_key = response.json()['config']['notifications']['webhook']['public_key']
        logger.debug('Public key is ' + public_key)
        
        try:
            check_authorized(signature, public_key, payload)
        except SignatureError:
            logger.error('Signature could not be verified')
            return {'statusCode': 400}
    else:
        logger.info('Neglecting to verify signature due to ALLOW_UNSIGNED env var')
    
    if 'repository' not in body or 'owner_name' not in body['repository']:
        logger.error('Unable to locate repository owner in API payload')
        return {'statusCode': 400, 'body': 'Can\'t find repo owner'}
    
    if body['repository']['owner_name'] not in repository_owners:
        logger.warning( '%s not in %s' % (body['repository']['owner_name'],
                                          str(repository_owners)))
        return {'statusCode': 403}
    
    # Pushes only
    if body['type'] != 'push':
        logger.info('Event is type %s -- not "push."  Ignoring.' % body['type'])
        return {'statusCode': 200}
    
    # We're not alerting anything but failures
    if body['state'] not in failure_states:
        logger.info('State is %s.  We only alert for %s' % (body['state'],
                                                             ', '.join(failure_states)))
        return {'statusCode': 200}
        
    alert_branches = os.environ.get("ALERT_BRANCHES")
        
    # Note that we will continue for all branches if none are specified
    if alert_branches is not None:
        branches_list = alert_branches.split(' ')
        if body['branch'] not in branches_list:
            logger.info('Branch is %s, but we are only alerting %s' % (body['branch'],
                                                                    ', '.join(branches_list)))
        return {'statusCode': 200}
    
    send_message(body)

    return {
        'statusCode': 200,
    }
    
def random_quote() -> str:
    with open('quotes.txt') as f:
        lines = [line for line in f.readlines() if len(line) > 0]
        
    return choice(lines)

def send_message(event):
    quote = random_quote()
    author = (event['committer_name'].split(' ')[0]  # First name
              if len(event['committer_name']) > 0
              else 'Someone')
    branch_name = event.get('branch')
    repo_name = event['repository']['name']
    footer = '%s/%s: %s' % (repo_name, event['branch'], event['build_url'])

    attachments = [{
        'text': '',
        'footer': footer
    }]
                     
    body = {
        'text': ('*%s*: %s' % (author, quote)),
        'attachments': attachments
    }
    
    print(str(body))
    requests.put(os.environ.get('SLACK_WEBHOOK'), data=json.dumps(body))

def check_authorized(self, signature, public_key, payload):
    """
    Convert the PEM encoded public key to a format palatable for pyOpenSSL,
    then verify the signature
    """
    pkey_public_key = load_publickey(FILETYPE_PEM, public_key)
    certificate = X509()
    certificate.set_pubkey(pkey_public_key)
    verify(certificate, signature, payload, str('sha1'))
