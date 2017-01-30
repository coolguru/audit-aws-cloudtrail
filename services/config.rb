
# user-visible definitions

coreo_aws_advisor_alert "cloudtrail-inventory" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc-inventory.html"
  include_violations_in_count false
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all trails in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["trails"]
  audit_objects ["object.trail_list.name"]
  operators ["=~"]
  alert_when [//]
  id_map "object.trail_list.name"
end

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
  id_map "stack.current_region"
end

coreo_aws_advisor_alert "cloudtrail-no-global-trails" do
  action :define
  service :user
  category "jsrunner"
  suggested_action "The metadata for this definition is defined in the jsrunner below. Do not put metadata here."
  level "jsrunner"
  objectives [""]
  audit_objects [""]
  operators [""]
  alert_when [true]
  id_map ""
end

# internal definitions

coreo_aws_advisor_alert "cloudtrail-trail-with-global" do
  action :define
  service :cloudtrail
  include_violations_in_count false
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
  id_map "stack.current_region"
end

coreo_aws_advisor_cloudtrail "advise-cloudtrail" do
  action :advise
  alerts
    ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}
    - cloudtrail-trail-with-global
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
result['violations'] = {};
var nRegionsWithGlobal = 0;
var nViolations = 0;
for(var region in json_input['violations']) {
    result['violations'][region] = {};
    for (var key in json_input['violations'][region]) {
        if (json_input['violations'][region].hasOwnProperty(key)) {
            if (json_input['violations'][region][key]['violations']['cloudtrail-trail-with-global']) {
                nRegionsWithGlobal++;
            } else {
                nViolations++;
                result['violations'][region][key] = json_input['violations'][region][key];
            }
        }
    }
}

var noGlobalsAlert = {};
if (nRegionsWithGlobal == 0) {
    console.log(regionArray);
    regionArray.forEach(region => {
        nViolations++;
        noGlobalsMetadata =
            {
                'service': 'cloudtrail',
                'link' : 'http://kb.cloudcoreo.com/mydoc_cloudtrail-trail-with-global.html',
                'display_name': 'Cloudtrail global logging is disabled',
                'description': 'CloudTrail global service logging is not enabled for the selected regions.',
                'category': 'Audit',
                'suggested_action': 'Enable CloudTrail global service logging in at least one region',
                'level': 'Warning',
                'region': region
            };
        noGlobalsAlert =
            { violations:
                { 'cloudtrail-no-global-trails':
                noGlobalsMetadata
                },
                tags: []
            };
        var key = 'selected regions';
        console.log(result['violations'][region]);
        const regionKeys = Object.keys(result['violations']['region']);
        regionKeys.forEach(regionKey => {
            if (result['violations'][regionKey][region]) {
                result['violations'][regionKey][region]['violations']['cloudtrail-no-global-trails'] = noGlobalsMetadata;
            } else {
                result['violations'][regionKey][region] = noGlobalsAlert;
            }
        });
    });
}
result['number_of_violations'] = nViolations;
callback(result['violations']);
  EOH
end

coreo_uni_util_variables "cloudtrail-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-suppression-cloudtrail" do
  action :run
  provide_composite_access true
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  const fs = require('fs');
  const yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  const violations = json_input.violations;
  const result = {};
  let file_date = null;
  const regionKeys = Object.keys(violations);
  regionKeys.forEach(region => {
      result[region] = {};
      const violationKeys = Object.keys(violations[region]);
      violationKeys.forEach(violator_id => {
          result[region][violator_id] = {};
          result[region][violator_id].tags = violations[region][violator_id].tags;
          result[region][violator_id].violations = {};
          const ruleKeys = Object.keys(violations[region][violator_id].violations);
          ruleKeys.forEach(rule_id => {
              let is_violation = true;
              result[region][violator_id].violations[rule_id] = violations[region][violator_id].violations[rule_id];
              const suppressionRuleKeys = Object.keys(suppression);
              suppressionRuleKeys.forEach(suppress_rule_id => {
                  const suppressionViolatorNum = Object.keys(suppression[suppress_rule_id]);
                  suppressionViolatorNum.forEach(suppress_violator_num => {
                      const suppressViolatorIdKeys = Object.keys(suppression[suppress_rule_id][suppress_violator_num]);
                      suppressViolatorIdKeys.forEach(suppress_violator_id => {
                          file_date = null;
                          let suppress_obj_id_time = suppression[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                          if (rule_id === suppress_rule_id) {
  
                              if (violator_id === suppress_violator_id) {
                                  const now_date = new Date();
  
                                  if (suppress_obj_id_time === "") {
                                      suppress_obj_id_time = new Date();
                                  } else {
                                      file_date = suppress_obj_id_time;
                                      suppress_obj_id_time = file_date;
                                  }
                                  let rule_date = new Date(suppress_obj_id_time);
                                  if (isNaN(rule_date.getTime())) {
                                      rule_date = new Date(0);
                                  }
  
                                  if (now_date <= rule_date) {
  
                                      is_violation = false;
  
                                      result[region][violator_id].violations[rule_id]["suppressed"] = true;
                                      if (file_date != null) {
                                          result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                          result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                                      }
                                  }
                              }
                          }
                      });
                  });
              });
              if (is_violation) {
  
                  if (file_date !== null) {
                      result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = true;
                  } else {
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                  }
                  result[region][violator_id].violations[rule_id]["suppressed"] = false;
              }
          });
      });
  });
  
callback(result);
  EOH
end

coreo_uni_util_variables "cloudtrail-suppression-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-cloudtrail.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-table-cloudtrail" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    }catch(e) {
  
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end

coreo_uni_util_notify "advise-cloudtrail-json" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_CLOUDTRAIL_SEND_ON}'
  payload 'COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  }) 
end

## Create Notifiers

coreo_uni_util_jsrunner "cloudtrail-tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "cloudcoreo-jsrunner-commons",
          :version => "1.7.0"
        }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table-cloudtrail.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-cloudtrail.return}'
  function <<-EOH
  
const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;


const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, 
  ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCLOUDTRAIL = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const notifiers = AuditCLOUDTRAIL.getNotifiers();
callback(notifiers);
EOH
end

## Create rollup String

coreo_uni_util_jsrunner "cloudtrail-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "Violations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
EOH
end

coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :${AUDIT_AWS_CLOUDTRAIL_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action :${AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_CLOUDTRAIL_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

