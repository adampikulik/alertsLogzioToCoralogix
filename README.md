# alertsLogzioToCoralogix - Migrate alerts from Logz.io to Coralogix
AlertsLogzioToCoralogix.py is a tool which allows to migrate alerts from Logz.io to Coralogix

## Description
The tool was created to easily copy alerts from Logz.io to Coralogix. The script uses Coralogix Alerts API: [Coralogix - Alerts](https://coralogix.com/docs/alerts-api/)
It is not Coralogix official tool.

## Usage
python3 loadjson.py <input_file.json> <Alerts, Rules and Tags key> <Endpoint>
* <input_file.json> is mandatory
* <Alerts, Rules and Tags key> is mandatory
* <Endpoint> is optional (default: api.coralogix.com)

<b>Note</b>: The input file should contain only an array with alerts json objects. It is the value of the results field.

Endpoints can be found: https://coralogix.com/docs/coralogix-endpoints/#external-alerts
       
Example:
     python3 loadjson.py sample.json 12345678-12ab-12cd-3b4d-12345678abcd api.coralogix.com'

Example output:
```
Input File: sample1.json
API key matches the pattern.
Default endpoint set: "api.coralogix.com". Add the endpoint as an argument to change.
Process started at 2023/10/08 01:51:27
Creating the file: migrated_success_IDs_20231008-015127.out which will store all alerts' IDs which were successfully created on Coralogix.
----------------------------------------------------------------------------
Alert #1
Alert name: "User failed to login"
Query in Coralogix: (_exists_:user) AND (error_message:"Authentication failed")
API call to Coralogix...
Status code: 201
{"status":"success","message":"Alert created successfully","alert_id":["12345678-12ab-12cd-3b4d-12345678abcd"],"unique_identifier":["87654321-12ab-12cd-3b4d-abcdef123456"]}
```

## Mapping alerts
Because of differences between Logz.io and Coralogix after running the code there is a need to review alerts as they may need conditions changes. When you run the tool you get an information for each alert if an alert was created successfully or not, and also a hint that you should check conditions carefully as they were modified.

## Limitations
* the tool supports the aggregationType COUNT only (planning to add UNIQUE_COUNT)
* the tool 


## Delete created alerts
The tool creates a file migrated_success_IDs_<timestamp>.out which contains a list of alerts ID created in Coralogix. You can use the list to delete alerts which you created with the tool.


