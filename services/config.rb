# service-disabled

coreo_aws_advisor_alert "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-service-disabled.html"
  display_name "Cloudtrail Service is disabled"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs for each region."
  level "Warning"
  objectives ["trails"]
  formulas ["count"]
  audit_objects ["trail_list"]
  operators ["=="]
  alert_when [0]
end

coreo_aws_advisor_alert "cloudtrail-trail-with-global" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["trails"]
  audit_objects ["trail_list.include_global_service_events"]
  operators ["=="]
  alert_when [true]
  id_map "object.trail_list.name"
end

coreo_aws_advisor_alert "no-global-trails" do
  action :nothing
  service :cloudtrail
  category "Inventory"
  suggested_action "The metadata for this definition is defined in the jsrunner below. Do not put metadata here."
  level "Informational"
  objectives [""]
  audit_objects [""]
  operators [""]
  alert_when [true]
  id_map ""
end

coreo_aws_advisor_cloudtrail "advise-cloudtrail" do
  action :advise
  alerts ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}
  regions ${AUDIT_AWS_CLOUDTRAIL_REGIONS}
end

coreo_uni_util_jsrunner "cloudtrail-aggregate" do
  action :run
  json_input '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations":COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report}'
  function <<-EOH
var_regions = "${AUDIT_AWS_CLOUDTRAIL_REGIONS}";

let regionArrayJSON =  var_regions;
let regionArray = regionArrayJSON.replace(/'/g, '"');
regionArray = JSON.parse(regionArray);
let createRegionStr = '';
regionArray.forEach(region=> {
    createRegionStr+= region + ' ';
});


var result = {};
result['composite name'] = json_input['composite name'];
result['plan name'] = json_input['plan name'];
result['regions'] = var_regions;
result['number_of_checks'] = json_input['number_of_checks'];
result['number_of_violations'] = json_input['number_of_violations'];
result['number_violations_ignored'] = json_input['number_violations_ignored'];
result['violations'] = {};
var nRegionsWithGlobal = 0;
var nViolations = 0;
console.log('json_input: ' + JSON.stringify(json_input));
for (var key in json_input['violations']) {
  if (json_input['violations'].hasOwnProperty(key)) {
    console.log('--> checking key: ' + key);
    if (json_input['violations'][key]['violations']['cloudtrail-trail-with-global']) {
      console.log("Trail has a region with global: " + key);
      nRegionsWithGlobal++;
    } else {
      nViolations++;
      result['violations'][key] = json_input['violations'][key];
    }
  }
}
console.log('Number of regions with global: ' + nRegionsWithGlobal);
var noGlobalsAlert = {};
if (nRegionsWithGlobal == 0) {
  nViolations++;
  noGlobalsAlert =
          { violations:
            { 'no-global-trails':
               {
                'link' : 'http://kb.cloudcoreo.com/mydoc_cloudtrail-trail-with-global.html',
                'display_name': 'Cloudtrail global logging is disabled',
                'description': 'CloudTrail global service logging is not enabled for the selected regions.',
                'category': 'Audit',
                'suggested_action': 'Enable CloudTrail global service logging in at least one region',
                'level': 'Warning',
                'region': createRegionStr
               }
            },
            tags: []
          };
  var key = 'selected regions';
  console.log('saving global violation on key: ' + key + ' | violation: ' + JSON.stringify(noGlobalsAlert));
  result['violations']['selected-regions'] = noGlobalsAlert;
}
console.log('Number of violations: ' + nViolations);
result['number_of_violations'] = nViolations;
callback(result);
  EOH
end

coreo_uni_util_variables "update-advisor-output" do
  action :set
  variables([
       {'COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'}
      ])
end

coreo_uni_util_notify "advise-cloudtrail-json" do
  action :nothing
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_CLOUDTRAIL_SEND_ON}'
  payload 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

## Create Notifiers
coreo_uni_util_jsrunner "tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "cloudcoreo-jsrunner-commons",
          :version => "1.3.3"
        }       ])
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'
  function <<-EOH
  
const JSON = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}";
const AUDIT_NAME = 'cloudtrail';

const ARE_KILL_SCRIPTS_SHOWN = false;
const EC2_LOGIC = ''; // you can choose 'and' or 'or';
const EXPECTED_TAGS = ['example_2', 'example_1'];

const WHAT_NEED_TO_SHOWN = {
    OBJECT_ID: {
        headerName: 'AWS Object ID',
        isShown: true,
    },
    REGION: {
        headerName: 'Region',
        isShown: true,
    },
    AWS_CONSOLE: {
        headerName: 'AWS Console',
        isShown: true,
    },
    TAGS: {
        headerName: 'Tags',
        isShown: true,
    },
    AMI: {
        headerName: 'AMI',
        isShown: false,
    },
    KILL_SCRIPTS: {
        headerName: 'Kill Cmd',
        isShown: false,
    }
};

const VARIABLES = {
    NO_OWNER_EMAIL,
    OWNER_TAG,
    AUDIT_NAME,
    ARE_KILL_SCRIPTS_SHOWN,
    EC2_LOGIC,
    EXPECTED_TAGS,
    WHAT_NEED_TO_SHOWN,
    ALLOW_EMPTY,
    SEND_ON
};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCloudTrail = new CloudCoreoJSRunner(JSON, VARIABLES);
const notifiers = AuditCloudTrail.getNotifiers();
callback(notifiers);
EOH
end

## Create rollup String
coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
EOH
end

## Send Notifiers
coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :${AUDIT_AWS_CLOUDTRAIL_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action :${AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_CLOUDTRAIL_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_violations_ignored: COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

