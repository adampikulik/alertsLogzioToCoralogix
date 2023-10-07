# alertsLogzioToCoralogix - Migrate alerts from Logz.io to Coralogix
AlertsLogzioToCoralogix.py is a tool which allows to migrate alerts from Logz.io to Coralogix

## Description
The tool was created to easily copy alerts from Logz.io to Coralogix. The script uses Coralogix Alerts API: [Coralogix - Alerts](https://coralogix.com/docs/alerts-api/)

## Usage
python3 loadjson.py <input_file.json> <Alerts, Rules and Tags key> <Endpoint>
* <input_file.json> is mandatory
* <Alerts, Rules and Tags key> is mandatory
* <Endpoint> is optional (default: api.coralogix.com)
       
Example:
     python3 loadjson.py sample.json 12345678-12ab-12cd-3b4d-12345678abcd api.coralogix.com'

Endpoints can be found: https://coralogix.com/docs/coralogix-endpoints/#external-alerts
