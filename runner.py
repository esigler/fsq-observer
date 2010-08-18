#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2010 Eric Sigler, esigler@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import cgi
import time
import logging

import urllib
import httplib2
import oauth2 as oauth
import simplejson as json

############################ Settings/Config ##################################

sleep_interval = 2
latency_threshold = .5

stashboard_oauth_key = 'key-from-stashboard'
stashboard_oauth_secret = 'secret-from-stashboard'
stashboard_base_url = 'https://stashboard-host/api/v1'

fsq_oauth_key = 'consumer-key-from-foursquare-app-registration'
fsq_oauth_secret = 'consumer-secret-from-foursquare-app-registration'

fsq_user_key = 'valid-oauth-access-key-from-foursquare'
fsq_user_secret = 'valid-oauth-access-secret-from-foursquare'

client_headers = {'User-agent': 'stashboard-host:0.1'}

urls_to_check = {'web-foursquare-homepage': 'http://foursquare.com/',
                 'web-oauth-authorization-page': 'http://foursquare.com/oauth/authorize'
                 }

token_urls_to_check = {'oauth-get-request-token': 'http://foursquare.com/oauth/request_token',
                       'oauth-get-access-token': 'http://foursquare.com/oauth/access_token?'+
                                                 'x_auth_username=username@example.com&'+
                                                 'x_auth_password=dummy_passwd&x_auth_mode=client_auth'
                       }

logging.basicConfig(level=logging.DEBUG)

########################### Library functions #################################

def make_stashboard_request(partial_url, method, body_data=None):
    logging.debug('requesting stashboard url %s with method %s and data %s' % (partial_url, method, body_data))

    #Reminder: If you register your app w/Google, these won't be 'anonymous' anymore
    stashboard_consumer = oauth.Consumer(key='anonymous', secret='anonymous')
    stashboard_token = oauth.Token(stashboard_oauth_key, stashboard_oauth_secret)
    stashboard_client = oauth.Client(stashboard_consumer, token=stashboard_token)

    if body_data is not None:
        data = urllib.urlencode(body_data)
        return stashboard_client.request(stashboard_base_url+partial_url, method, body=data)
    else:
        return stashboard_client.request(stashboard_base_url+partial_url, method)

def get_current_status(service_name):
    logging.debug('getting current status for: %s' % service_name)

    resp, content = make_stashboard_request('/services/'+service_name+'/events/current', 'GET')
    event = json.loads(content)
    
    if 'status' not in event:
        raise Exception('Malformed response from stashboard')
    elif 'id' not in event['status']:
        raise Exception('Malformed response from stashboard')
    else:
        return event['status']['id']

def update_current_status(service_id, status_msg, status_id):
    logging.debug('updating current status for: %s, to: %s, with: %s' % (service_id, status_id, status_msg))

    make_stashboard_request('/services/'+service_id+'/events', 'POST', body_data={
        "message": status_msg,
        "status": status_id
    })

############################ Testing Helpers ##################################

def http_check(service_id, request_url):
    logging.debug('requesting URL for basic HTTP check: %s' % request_url)
    http_client = httplib2.Http()
    
    try:
        start_time = time.time()
        resp, content = http_client.request(request_url, headers=client_headers)
        elapsed_time = (time.time() - start_time)

        if resp.status != 200:
            if get_current_status(service_id) != 'down':
                update_current_status(service_id=service_id,
                                      status_id='down',
                                      status_msg='GET did not return an HTTP 200 OK status')
        else:
            if get_current_status(service_id) != 'up':
                update_current_status(service_id=service_id,
                                      status_id='up',
                                      status_msg='GET returned an HTTP 200 OK status')

        if elapsed_time > latency_threshold:
            if get_current_status(service_id) != 'warning':
                update_current_status(service_id=service_id,
                                      status_id='warning',
                                      status_msg='GET took longer than '+str(latency_threshold)+' seconds to load')

        return resp, content
    except Exception, e:
        #FIXME: Horrible kludge that doesn't really catch the httplib2.HttpLib2Error
        #Httplib2/Python 2.5 bug: http://code.google.com/p/httplib2/issues/detail?id=96
        if str(e) == '\'NoneType\' object has no attribute \'makefile\'':
            if get_current_status(service_id) != 'down':
                update_current_status(service_id=service_id,
                                      status_id='down',
                                      status_msg='GET did not respond')
            return {'resp': '', 'content': ''}
        else:
            raise Exception(e)

#FIXME: Yup, this is a big ugly duplication I'm not thrilled about here.  Suggestions?
def oauth_check(service_id, request_url, method='GET', token=None, secret=None):
    logging.debug('requesting oauth for url: %s' % request_url)
    
    fsq_consumer = oauth.Consumer(key=fsq_oauth_key, secret=fsq_oauth_secret)
    if token is not None:
        fsq_token = oauth.Token(token, secret)
        fsq_client = oauth.Client(fsq_consumer, token=fsq_token)
    else:
        fsq_client = oauth.Client(fsq_consumer)

    try:
        start_time = time.time()
        resp, content = fsq_client.request(request_url, method, headers=client_headers)
        elapsed_time = (time.time() - start_time)

        if resp.status != 200:
            if get_current_status(service_id) != 'down':
                update_current_status(service_id=service_id,
                                      status_id='down',
                                      status_msg=method+' did not return an HTTP 200 OK status')
        else:
            if get_current_status(service_id) != 'up':
                update_current_status(service_id=service_id,
                                      status_id='up',
                                      status_msg=method+' returned an HTTP 200 OK status')

        if elapsed_time > latency_threshold:
            if get_current_status(service_id) != 'warning':
                update_current_status(service_id=service_id,
                                      status_id='warning',
                                      status_msg=method+' took longer than '+str(latency_threshold)+' seconds to load')

        return resp, content
    except Exception, e:
        #FIXME: Horrible kludge that doesn't really catch the httplib2.HttpLib2Error
        #Httplib2/Python 2.5 bug: http://code.google.com/p/httplib2/issues/detail?id=96
        if str(e) == '\'NoneType\' object has no attribute \'makefile\'':
            if get_current_status(service_id) != 'down':
                update_current_status(service_id=service_id,
                                      status_id='down',
                                      status_msg=method+' did not respond')
            return {'resp': '', 'content': ''}
        else:
            raise Exception(e)

############################# Status checks ###################################

def oauth_tokens_check(service_id, request_url):
    logging.info('RUNNING TEST: '+service_id)
    resp, content = oauth_check(service_id, request_url)
    decoded = dict(cgi.parse_qsl(content))

    if 'oauth_token' not in decoded:
        if get_current_status(service_id) != 'down':
            update_current_status(service_id=service_id,
                                  status_id='down',
                                  status_msg='No valid token could be decoded')
    elif 'oauth_token_secret' not in decoded:
        if get_current_status(service_id) != 'down':
            update_current_status(service_id=service_id,
                                  status_id='down',
                                  status_msg='No valid key could be decoded')
    else:
        if get_current_status(service_id) != 'up':
            update_current_status(service_id=service_id,
                                  status_id='up',
                                  status_msg='Valid token & key decoded')

def api_test_check():
    logging.info('RUNNING TEST: api-v1-test-endpoint')
    resp, content = http_check('api-v1-test-endpoint', 'http://api.foursquare.com/v1/test.json')

    try:
        decoded = json.loads(content)

        if 'response' not in decoded:
            if get_current_status('api-v1-test-endpoint') != 'down':
                update_current_status(service_id='api-v1-test-endpoint',
                                      status_id='down',
                                      status_msg='No valid JSON could be decoded')
        elif decoded['response'] != 'ok':
            if get_current_status('api-v1-test-endpoint') != 'down':
                update_current_status(service_id='api-v1-test-endpoint',
                                      status_id='down',
                                      status_msg='No valid JSON could be decoded')
        else:
            if get_current_status('api-v1-test-endpoint') != 'up':
                update_current_status(service_id='api-v1-test-endpoint',
                                      status_id='up',
                                      status_msg='Valid JSON decoded')

    except ValueError, e:
        if str(e) == 'No JSON object could be decoded':
            if get_current_status('api-v1-test-endpoint') != 'down':
                update_current_status(service_id='api-v1-test-endpoint',
                                      status_id='down',
                                      status_msg='No valid JSON could be decoded')

def api_checkin_check():
    logging.info('RUNNING TEST: api-v1-create-checkin')
    resp, content = oauth_check('api-v1-create-checkin',
                                'http://api.foursquare.com/v1/checkin.json?shout=testing',
                                method='POST',
                                token=fsq_user_key,
                                secret=fsq_user_secret)

    try:
        decoded = json.loads(content)

        if 'checkin' not in decoded:
            if get_current_status('api-v1-create-checkin') != 'down':
                update_current_status(service_id='api-v1-create-checkin',
                                      status_id='down',
                                      status_msg='No valid JSON could be decoded')
            checkin_id = 0
        elif 'id' not in decoded['checkin']:
            if get_current_status('api-v1-create-checkin') != 'down':
                update_current_status(service_id='api-v1-create-checkin',
                                      status_id='down',
                                      status_msg='No valid JSON could be decoded')
            checkin_id = 0
        else:
            if get_current_status('api-v1-create-checkin') != 'up':
                update_current_status(service_id='api-v1-create-checkin',
                                      status_id='up',
                                      status_msg='Valid JSON decoded')
            checkin_id = decoded['checkin']['id']

    except ValueError, e:
        if str(e) == 'No JSON object could be decoded':
            if get_current_status('api-v1-create-checkin') != 'down':
                update_current_status(service_id='api-v1-create-checkin',
                                      status_id='down',
                                      status_msg='No valid JSON could be decoded')
        checkin_id = 0
    
    return checkin_id

def api_history_check(checkin_id):
  logging.info('RUNNING TEST: api-v1-get-history')
  resp, content = oauth_check('api-v1-get-history',
                              'http://api.foursquare.com/v1/history.json?l=1&since_id='+str(checkin_id),
                              token=fsq_user_key,
                              secret=fsq_user_secret)

  try:
      decoded = json.loads(content)

      if 'checkins' not in decoded:
          if get_current_status('api-v1-get-history') != 'down':
              update_current_status(service_id='api-v1-get-history',
                                    status_id='down',
                                    status_msg='No valid JSON could be decoded')
      elif len(decoded['checkins']) != 1:
          if get_current_status('api-v1-get-history') != 'down':
              update_current_status(service_id='api-v1-get-history',
                                    status_id='down',
                                    status_msg='Invalid history results')
      else:
          if get_current_status('api-v1-get-history') != 'up':
              update_current_status(service_id='api-v1-get-history',
                                    status_id='up',
                                    status_msg='Valid JSON decoded')

  except ValueError, e:
      if str(e) == 'No JSON object could be decoded':
          if get_current_status('api-v1-get-history') != 'down':
              update_current_status(service_id='api-v1-get-history',
                                    status_id='down',
                                    status_msg='No valid JSON could be decoded')


########################### Main / test runner ################################

def main():
    logging.debug("Starting runner")

    for key in urls_to_check.keys():
        http_check(key, urls_to_check[key])
        time.sleep(sleep_interval)

    api_test_check()
    time.sleep(sleep_interval)

    for key in token_urls_to_check.keys():
        oauth_tokens_check(key, token_urls_to_check[key])
        time.sleep(sleep_interval)

    #FIXME: Uh, this could get ugly (test every minute = 1440 "checkins"/day)
    checkin_id = api_checkin_check()
    time.sleep(sleep_interval)

    api_history_check(checkin_id)
    time.sleep(sleep_interval)

    logging.debug("Finishing runner")

if __name__ == "__main__":
    main()
