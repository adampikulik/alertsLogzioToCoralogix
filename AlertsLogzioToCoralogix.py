################################################################################################
# Tool to migrate Logz.io alerts to Coralogix Alerts
# Source: Logz.io alerts exported to json
# Target: The tool will create Terraform file to be used with Coralogix Terraform Provider
################################################################################################
#from contextlib import nullcontext

import json
import time
import requests
import re
import sys

################################################################################################
# Set global variables
################################################################################################
global input_filename
global endpoint
global apiKey

################################################################################################
# Check arguments
################################################################################################
input_filename = ""
endpoint = "api.coralogix.com"
apiKey = ""

if len(sys.argv) < 3:
    print('Error: Provide Alerts, Rules and Tags key and the input json file name as arguments.')
    print('Usage:')
    print('     python3 loadjson.py <input_file.json> <Alerts, Rules and Tags key> <Endpoint>')
    print('       - <input_file.json> is mandatory')
    print('       - <Alerts, Rules and Tags key> is mandatory')
    print('       - <Endpoint> is optional (default: api.coralogix.com)')
    print('Example:')
    print('     python3 loadjson.py sample.json 0738703-35c6-42ba-8b3d-9b4dda498e02 api.coralogix.com')
    print("Exiting the program...")
    sys.exit(0)

try:
    input_filename = sys.argv[1]
    if re.search('\.json$', input_filename):
        print('Input File: '+ input_filename)
    else:
        print('Incorect file name: '+ input_filename)
        print("Exiting the program...")
        sys.exit(0)
except NameError:
    print('Provide the the input json file name as an argument.')
    print("Exiting the program...")

try:
    apiKey = sys.argv[2]
    if re.search('^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$', apiKey):
        print('API key matches the pattern.')
    else:
        print('Incorect API key: '+ apiKey)
        print("Exiting the program...")
        sys.exit(0)
except NameError:
    print('Provide Alerts, Rules and Tags key as an argument')
    print("Exiting the program...")
    sys.exit(0)

if len(sys.argv) < 3:
    endpoint = sys.argv[3]
    if re.search('api\.((app|eu2|cx\d{3})\.)?coralogix(sg)?\.(com|in|us)', endpoint):
        print('API key matches the pattern.')
    else:
        print('Incorect endpoint: '+ str(endpoint))
        print("Exiting the program...")
        sys.exit(0)
else:
    print('Default endpoint set: "api.coralogix.com". Add the endpoint as an argument to change.')

################################################################################################
# Set base variables
################################################################################################

json_file = open(input_filename)
json_array = json.load(json_file)
store_list = []
cx_alerts_list = []
count = 0

################################################################################################
# Function to build a query from the Logzio filter part
################################################################################################
def build_filter_query(filter_query,operator):
    item_number = 0
    filter_query_lucene = ""

    for filter_item in filter_query:
        if filter_item.get('match_phrase') != None:
            key_list = list(filter_item['match_phrase'].keys())
            filter_field = key_list[0]
            filter_field_value = filter_item['match_phrase'][filter_field]['query']
            if item_number>0:
                filter_query_lucene = filter_query_lucene + ' ' + operator + ' '
            filter_query_lucene = filter_query_lucene + filter_field +':"'+ filter_field_value +'"'

        if filter_item.get('range') != None:
            key_list = list(filter_item['range'].keys())
            filter_field = key_list[0]
            if 'gte' in filter_item['range'][filter_field]:
                filter_field_from_value = '[' + str(filter_item['range'][filter_field]['gte'])
            if 'gt' in filter_item['range'][filter_field]:
                filter_field_from_value = '{' + str(filter_item['range'][filter_field]['gt'])
            if 'lte' in filter_item['range'][filter_field]:
                filter_field_to_value = str(filter_item['range'][filter_field]['lte']) + ']'
            if 'lt' in filter_item['range'][filter_field]:
                filter_field_to_value = str(filter_item['range'][filter_field]['lt']) + '}'
            if item_number>0:
                filter_query_lucene = filter_query_lucene + ' ' + operator + ' '
            filter_query_lucene = filter_query_lucene + filter_field +'.numeric: ' + str(filter_field_from_value) +' TO '+ str(filter_field_to_value)
        
        if filter_item.get('exists') != None:
            filter_field_value = filter_item['exists']['field']
            if item_number>0:
                filter_query_lucene = filter_query_lucene + ' ' + operator + ' '
            filter_query_lucene = filter_query_lucene + '_exists_:"'+ filter_field_value +'"'

        item_number = item_number + 1

    return filter_query_lucene

################################################################################################
# Function to parse the query
################################################################################################
def parseQuery(query):
    # Remove new lines characters
    query = query.rstrip()
    # Replace > with the range Example: delay_ms:>1800000
    query = re.sub('([A-z\@\.\d\_]+)\:\>(\d+)', '\\1.numeric:[\\2 TO *]', query)
    # Replace > with the range Example: delay_ms:<1800000
    query = re.sub('([A-z\@\.\d\_]+)\:\<(\d+)', '\\1.numeric:[* TO \\2]', query)
    # Replace regex queries. Example: host:*outbound-1*
    query = re.sub('([A-z\@\.\d\_\-]+)\:\*([A-z\@\.\d\_\-]+)\*', '\\1.keyword:/.*\\2.*/', query)
    # Replace regex queries. Example: host:b2b-prod*
    query = re.sub('([A-z\@\.\d\_\-]+)\:([A-z\@\.\d\_\-]+)\*', '\\1.keyword:/\\2.*/', query)
    # Replace regex queries. Example: host:*b2b-prod
    query = re.sub('([A-z\@\.\d\_\-]+)\:\*([A-z\@\.\d\_\-]+)', '\\1.keyword:/.*\\2/', query)
    # Replace regex queries. Example: tags:"*production"
    query = re.sub('([A-z\@\.\d\_\-]+)\:\"\*([A-z\@\.\d\_\-]+)\"', '\\1.keyword:/.*\\2/', query)
    # Replace regex queries. Example: tags:"production*"
    query = re.sub('([A-z\@\.\d\_\-]+)\:\"([A-z\@\.\d\_\-]+)\*\"', '\\1.keyword:/\\2.*/', query)
    # Replace * with notihing. Example: *
    query = re.sub('^\*$', '', query)
    # Replace + next to words replace with AND. Example: +Ending +flow +execution
    query = re.sub('\s\+([^\s]+)', 'AND \\1', query)
    # Remove + next to words at the beginnig of the query. Example: +Ending +flow +execution
    query = re.sub('^\+([^\s]+)', '\\1', query)
    return query

################################################################################################
# HTTP Request using Coralogix Alerts API to create an alert in Coralogix
################################################################################################
def APIcall(alert_payload):
    # print ('running API call')
    url = "https://" + endpoint + "/api/v2/external/alerts/"

    # payload = json.dumps(alert_payload)
    payload = alert_payload

    # print(payload)
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+ apiKey +''
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    if response.status_code >= 300:
        print(payload)

    print('Status code: ' + str(response.status_code))
    print(response.text)

    # List of successful alerts API requests - Update the file
    migrated_success_IDs_file.write(re.sub('.*\"status\":\"success\",.*?\"alert_id\"\:\[\"([^\"]+)\"\].*', '\\1\n', response.text))

    return response.text

################################################################################################
# API - Build MORE/LESS THAN alert
################################################################################################
def APIcreate_MoreLessThan(cx_alert):
    alert=""
    cx_alert['log_filter.text'] = json.dumps(cx_alert['log_filter.text'])
    
    alert="""{{
    "name": {name},
    "severity": "{severity}",
    "expiration": null,
    "is_active": false,
    "log_filter": {{
        "text": {query},
        "category": [],
        "filter_type": "text",
        "severity": [],
        "application_name": [],
        "subsystem_name": [],
        "computer_name": [],
        "class_name": [],
        "ip_address": [],
        "method_name": []
    }},
    "condition": {{
        "condition_type": "{operator}",
        "threshold": {threshold},
        "timeframe": "{timeframe}",
        "group_by": "{groupby}",
        "group_by_lvl2": "{groupby2}"
    }},
    "notifications": {{
        "emails": [],
        "integrations": []
    }},
    "notify_every": {notify_every},
    "description": {description},
    "active_when": null,
    "lastTriggered": "Never triggered",
    "notif_payload_filter": [],
    "notify_on_resolved": false,
    "notify_group_by_only_alerts": false,
    "notify_per_group_by_value": false,
    "meta_labels": ["logzio"],
    "show_in_insight": {{
        "retriggeringPeriodSeconds": {notify_every},
        "notifyOn": "triggered_only"
    }},
    "notification_groups": [
        {{
            "groupByFields": [],
            "notifications": []
        }}
    ]
}}
"""
    
    d = {"name": cx_alert['name'], "description": cx_alert['description'], "severity": cx_alert['severity'], "notify_every": cx_alert['notify_every'], "query": cx_alert['log_filter.text'], "operator": cx_alert['condition.condition_type'], "threshold": cx_alert['threshold'], "timeframe": cx_alert['condition.timeframe'], "groupby": cx_alert['condition.group_by'], "groupby2": cx_alert['condition.group_by_lvl2']}
    
    return alert.format(**d)

################################################################################################
# Create Coralogix alert based on the type
################################################################################################
def create_CX_alert(cx_alert, alert_type, count):
    # print('Try to build the alert: ' + cx_alert['name'] + '. Type: "'+ alert_type +'".')
    if alert_type == 'COUNT':
        # print('More/Less than alert created. Name: "'+ cx_alert['name'] +'".')
        #created_alert = create_moreThan(cx_alert, count)
        alert_payload = APIcreate_MoreLessThan(cx_alert)
        print('API call to Coralogix...')
        response = APIcall(alert_payload)
    elif alert_type == 'UNIQUE_COUNT':
        print('Unique count alert created. Name: '+ cx_alert['name'] +'.')
        response=""
    else:
        print('Not supported type: "'+ alert_type +'". Alert: '+ cx_alert['name'] +' has been skipped. Need to create it manually.')
        response=""

    #print('Writing to file... The alert: "'+ cx_alert['name'] +'".')

    return response
    # ========================================================

################################################################################################
# Map Logz.io data to Coralogix alert fields
################################################################################################
def map_to_CX(store_details, severity):
    # Create Coralogix alert
    cx_alert = {}  
    # cx_alert['id'] = "12345abc-12ab-12ab-12ab-12345678abcd" # Fake ID to keep the structure
    cx_alert['name'] = store_details['title']
    cx_alert['description'] = store_details['description']
    # Severity Logz.io : Coralogix mapping: "INFO":"info" "LOW":"info" "MEDIUM":"warning" "HIGH":"error" "SEVERE":"critical"
    match severity:
        case "info":
            cx_alert['severity'] = "Info"
            cx_alert['threshold'] = store_details['INFO']
        case "low":
            cx_alert['severity'] = "Info"
            cx_alert['threshold'] = store_details['LOW']
        case "medium":
            cx_alert['severity'] = "Warning"
            cx_alert['threshold'] = store_details['MEDIUM']
        case "high":
            cx_alert['severity'] = "Error"
            cx_alert['threshold'] = store_details['HIGH']
        case "severe":
            cx_alert['severity'] = "Critical"
            cx_alert['threshold'] = store_details['SEVERE']
    # ===================================================
    cx_alert['is_active'] = store_details['enabled']
    cx_alert['log_filter.text'] = store_details['full_query']
    
    # Operator Logz.io: "LESS_THAN" "GREATER_THAN" "LESS_THAN_OR_EQUALS" "GREATER_THAN_OR_EQUALS" "EQUALS" "NOT_EQUALS"
    match store_details['operator']:
        case "LESS_THAN":
            cx_alert['condition.condition_type'] = "less_than"
        case "GREATER_THAN":
            cx_alert['condition.condition_type'] = "more_than"
        case "LESS_THAN_OR_EQUALS":
            cx_alert['condition.condition_type'] = "less_than"
            cx_alert['threshold'] = cx_alert['threshold'] + 1
        case "GREATER_THAN_OR_EQUALS":
            cx_alert['condition.condition_type'] = "more_than"
            cx_alert['threshold'] = cx_alert['threshold'] - 1
        case "EQUALS":
            cx_alert['condition.condition_type'] = "less_than"
            cx_alert['threshold'] = cx_alert['threshold'] + 1
            print('Logz.io Operator is EQUALS for the alert: "' + store_details['title'] + '". Check the condtion in Coralogix.')
        case "NOT_EQUALS":
            cx_alert['condition.condition_type'] = "more_than"
            cx_alert['threshold'] = cx_alert['threshold'] + 1
            print('Logz.io Operator is NOT_EQUALS for the alert: "' + store_details['title'] + '". Check the condtion in Coralogix.')
    # ========================================================

    # Logz.io allows to set the timeframe from 5 to 1440 minutes
    # Coralogix possible values: 5Min, 10Min, 15Min, 20Min, 30Min, 1H, 2H, 3H, 4H, 6H, 12H, 24H, 36H
    if store_details['searchTimeFrameMinutes'] > 0 and store_details['searchTimeFrameMinutes'] < 7:
        cx_alert['condition.timeframe'] = "5Min"
    elif store_details['searchTimeFrameMinutes'] >=7  and store_details['searchTimeFrameMinutes'] < 12:
        cx_alert['condition.timeframe'] = "10Min"
    elif store_details['searchTimeFrameMinutes'] >=13  and store_details['searchTimeFrameMinutes'] < 17:
        cx_alert['condition.timeframe'] = "15Min"
    elif store_details['searchTimeFrameMinutes'] >=17  and store_details['searchTimeFrameMinutes'] < 25:
        cx_alert['condition.timeframe'] = "20Min"
    elif store_details['searchTimeFrameMinutes'] >=25  and store_details['searchTimeFrameMinutes'] < 45:
        cx_alert['condition.timeframe'] = "30Min"
    elif store_details['searchTimeFrameMinutes'] >=45  and store_details['searchTimeFrameMinutes'] < 90:
        cx_alert['condition.timeframe'] = "1H"
    elif store_details['searchTimeFrameMinutes'] >=90  and store_details['searchTimeFrameMinutes'] < 210:
        cx_alert['condition.timeframe'] = "2H"
    elif store_details['searchTimeFrameMinutes'] >=210  and store_details['searchTimeFrameMinutes'] < 270:
        cx_alert['condition.timeframe'] = "4H"
    elif store_details['searchTimeFrameMinutes'] >=270  and store_details['searchTimeFrameMinutes'] < 420:
        cx_alert['condition.timeframe'] = "6H"
    elif store_details['searchTimeFrameMinutes'] >=420  and store_details['searchTimeFrameMinutes'] < 780:
        cx_alert['condition.timeframe'] = "12H"
    elif store_details['searchTimeFrameMinutes'] >=780  and store_details['searchTimeFrameMinutes'] <= 1440:
        cx_alert['condition.timeframe'] = "24H"
    elif store_details['searchTimeFrameMinutes'] >=1441:
        cx_alert['condition.timeframe'] = "36H"
    # ========================================================

    # Notify which alerts' timeframes were modified
    if not store_details['searchTimeFrameMinutes']==5 and not store_details['searchTimeFrameMinutes']==10 and not store_details['searchTimeFrameMinutes']==15 and not store_details['searchTimeFrameMinutes']==20 and not store_details['searchTimeFrameMinutes']==30 and not store_details['searchTimeFrameMinutes']==60 and not store_details['searchTimeFrameMinutes']==120 and not store_details['searchTimeFrameMinutes']==240 and not store_details['searchTimeFrameMinutes']==360 and not store_details['searchTimeFrameMinutes']==720 and not store_details['searchTimeFrameMinutes']==1440 and not store_details['searchTimeFrameMinutes']==2160:
        print('Logz.io Timeframe is ' + str(store_details['searchTimeFrameMinutes']) + ' for the alert: ' + store_details['title'] + '. In Coralogix mapped to ' + cx_alert['condition.timeframe'] + '. Check the condition in Coralogix.')
    # ========================================================

    if len(store_details['groupBy']) == 1:
        cx_alert['condition.group_by'] = store_details['groupBy'][0]
        cx_alert['condition.group_by_lvl2'] = ""
    elif len(store_details['groupBy']) == 2:
        cx_alert['condition.group_by'] = store_details['groupBy'][0]
        cx_alert['condition.group_by_lvl2'] = store_details['groupBy'][1]
    else:
        cx_alert['condition.group_by'] = ""
        cx_alert['condition.group_by_lvl2'] = ""

    # Notify every is in seconds and Logz.io suppressNotificationsMinutes in minutes
    cx_alert['notify_every'] = store_details['suppressNotificationsMinutes'] * 60

    # Create alerts
    created_alert = create_CX_alert(cx_alert, store_details['aggregationType'], store_details['count'])
    return created_alert

    # ========================================================

################################################################################################
# MAIN PROGRAM
################################################################################################
timestring = time.strftime("%Y%m%d-%H%M%S")

print('Process started at ' + str(time.strftime("%Y/%m/%d %H:%M:%S")))

print('Creating the file: migrated_success_IDs_' + str(timestring) + '.out which will store all alerts\' IDs which were successfully created on Coralogix.')
migrated_success_IDs_file = open('migrated_success_IDs_' + str(timestring) + '.out', 'a')

with open('report' + str(timestring) + '.log', 'a') as report_file:

    for item in json_array:
        count += 1
        print('----------------------------------------------------------------------------')
        print('Alert #'+ str(count))
        cx_alert = {}
        store_details = {"enabled":None, "output":None, "LOW":None, "MEDIUM":None, "HIGH":None}
        store_details['count'] = str(count)
        store_details['enabled'] = item['enabled']
        store_details['title'] = json.dumps(item['title'])
        print ('Alert name: '+store_details['title'])
        store_details['description'] = json.dumps(item['description'])
        store_details['recipients_emails'] = item['output']['recipients']['emails']
        store_details['recipients_notificationEndpointIds'] = item['output']['recipients']['notificationEndpointIds']
        store_details['suppressNotificationsMinutes'] = item['output']['suppressNotificationsMinutes']
        store_details['searchTimeFrameMinutes'] = item['searchTimeFrameMinutes']
        store_details['query'] = item['subComponents'][0]['queryDefinition']['query']
        store_details['must'] = item['subComponents'][0]['queryDefinition']['filters']['bool']['must']
        store_details['should'] = item['subComponents'][0]['queryDefinition']['filters']['bool']['should']
        store_details['filter'] = item['subComponents'][0]['queryDefinition']['filters']['bool']['filter']
        store_details['must_not'] = item['subComponents'][0]['queryDefinition']['filters']['bool']['must_not']
        store_details['groupBy'] = item['subComponents'][0]['queryDefinition']['groupBy']
        store_details['aggregationType'] = item['subComponents'][0]['queryDefinition']['aggregation']['aggregationType']
        store_details['fieldToAggregateOn'] = item['subComponents'][0]['queryDefinition']['aggregation']['fieldToAggregateOn']
        store_details['operator'] = item['subComponents'][0]['trigger']['operator']
        store_details['full_query']=""
        store_details['full_query'] = parseQuery(store_details['query'])

        if len(store_details['must'])>0 or len(store_details['should'])>0 or len(store_details['filter'])>0 or len(store_details['must_not'])>0:
            if store_details['full_query'] != "":
                # Taking a query and adding the AND operator.
                # The query can't be empty. If the query is empty operator is not added as it is not needed.
                # Example: "looking for a text string" AND
                store_details['full_query'] = re.sub('^(.+)$', '(\\1) AND ', store_details['full_query'])

            # Call the function to build a query from the "must" filter.
            if len(store_details['must'])>0:
                must = build_filter_query(store_details['must'],'AND')
                store_details['full_query'] = store_details['full_query'] +'('+ must +')'
            # Call the function to build a query from the "should" filter.
            if len(store_details['should'])>0:
                if len(store_details['must'])>0:
                    store_details['full_query'] = re.sub('^(.+)$', '\\1 AND ', store_details['full_query'])
                should = build_filter_query(store_details['should'],'OR')
                store_details['full_query'] = store_details['full_query'] +'('+ should +')'
            # Call the function to build a query from the "filter" filter.
            if len(store_details['filter'])>0:
                if len(store_details['must'])>0 or len(store_details['should'])>0:
                    store_details['full_query'] = re.sub('^(.+)$', '\\1 AND ', store_details['full_query'])
                filter = build_filter_query(store_details['filter'],'AND')
                store_details['full_query'] = store_details['full_query'] +'('+ filter +')'
            # Call the function to build a query from the "filter" filter.
            if len(store_details['must_not'])>0:
                #if len(store_details['must'])>0 or len(store_details['should'])>0:
                store_details['full_query'] = re.sub('^(.+)$', '\\1NOT ', store_details['full_query'])
                must_not = build_filter_query(store_details['must_not'],'NOT')
                store_details['full_query'] = store_details['full_query'] + must_not
        
        print('Query in Coralogix: ' + str(store_details['full_query']))

        # Create an alert for each severity
        # Logz.io possible values: "INFO" "LOW" "MEDIUM" "HIGH" "SEVERE"
        try:
            store_details['INFO'] = item['subComponents'][0]['trigger']['severityThresholdTiers']['INFO']
            cx_alert = map_to_CX(store_details, "info")
            #store_list.append(store_details)
            #cx_alerts_list.append(cx_alert)
            #TF_file.write(cx_alert)
        except KeyError:
            pass
        try:
            store_details['LOW'] = item['subComponents'][0]['trigger']['severityThresholdTiers']['LOW']
            cx_alert = map_to_CX(store_details, "low")
            #store_list.append(store_details)
            #cx_alerts_list.append(cx_alert)
            #TF_file.write(cx_alert)
        except KeyError:
            pass
        try:
            store_details['MEDIUM'] = item['subComponents'][0]['trigger']['severityThresholdTiers']['MEDIUM']
            cx_alert = map_to_CX(store_details, "medium")
            #store_list.append(store_details)
            #cx_alerts_list.append(cx_alert)
            #TF_file.write(cx_alert)
        except KeyError:
            pass
        try:
            store_details['HIGH'] = item['subComponents'][0]['trigger']['severityThresholdTiers']['HIGH']
            cx_alert = map_to_CX(store_details, "high")
            #store_list.append(store_details)
            #cx_alerts_list.append(cx_alert)
            #TF_file.write(cx_alert)
        except KeyError:
            pass
        try:
            store_details['SEVERE'] = item['subComponents'][0]['trigger']['severityThresholdTiers']['SEVERE']
            cx_alert = map_to_CX(store_details, "severe")
            #store_list.append(store_details)
            #cx_alerts_list.append(cx_alert)
            #TF_file.write(cx_alert)
        except KeyError:
            pass

        # store_list.append(store_details)
        # cx_alerts_list.append(cx_alert)

    #json_dump = json.dumps(store_list)
    #cx_alerts_json_dump = json.dumps(cx_alerts_list)

    # List of successful alerts API requests - Closing the file
    migrated_success_IDs_file.flush()
    migrated_success_IDs_file.close()

