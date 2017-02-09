
# user-visible engine-powered rule definitions

# TODO: inventory doc links

coreo_aws_rule "cloudtrail-inventory" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc-inventory.html"
  include_violations_in_count false
  display_name "Cloudtrail Inventory"
  description "This rule performs an inventory on all trails in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  meta_cis_id "99.999"
  objectives ["trails"]
  audit_objects ["object.trail_list.name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.trail_list.name"
end

coreo_aws_rule "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-service-disabled.html"
  display_name "Cloudtrail Service is Disabled"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs for each region."
  level "Warning"
  meta_cis_id "99.998"
  objectives ["trails"]
  formulas ["count"]
  audit_objects ["trail_list"]
  operators ["=="]
  raise_when [0]
  id_map "stack.current_region"
end

# TODO: rules that are service=user should not require objectives,audit_objects,operators,raise_when,id_map

coreo_aws_rule "cloudtrail-no-global-trails" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-trail-with-global.html"
  display_name "Cloudtrail Global Logging is Disabled"
  suggested_action "Enable CloudTrail global service logging in at least one region"
  description "CloudTrail global service logging is not enabled for the selected regions."
  level "Warning"
  meta_cis_id "99.997"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map ""
end

# end of user-visible content. Remaining resources are system-defined

coreo_aws_rule "cloudtrail-trail-with-global" do
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
  raise_when [true]
  id_map "stack.current_region"
end

# cross-resource variable holder

coreo_uni_util_variables "planwide" do
  action :set
  variables([
       {'COMPOSITE::coreo_uni_util_variables.planwide.initialized' => true},
       {'COMPOSITE::coreo_uni_util_variables.planwide.audit_result' => 'waiting'}
      ])
end

# audit result
# incomplete
# na (no audit resources)
# <blank>
# passed
# violations found
# waiting...

coreo_uni_util_jsrunner "cloudtrail-form-advisor-rule-list" do
  action :run
  json_input '{}'
  function <<-EOH
    var user_specified_rules = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";
    user_specified_rules = user_specified_rules.replace(/\\]/, ",'cloudtrail-trail-with-global']");
    coreoExport('rule_list_for_advisor', user_specified_rules);
    callback();
  EOH
end

# TODO: allow array to be generated from jsrunner so an interval rule def can be taken out of the user var array

coreo_aws_rule_runner_cloudtrail "advise-cloudtrail" do
  action :run
  rules ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}
  #alerts COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-form-advisor-rule-list.rule_list_for_advisor
  regions ${AUDIT_AWS_CLOUDTRAIL_REGIONS}
end

coreo_uni_util_variables "update-planwide-1" do
  action :set
  variables([
       {'COMPOSITE::coreo_uni_util_variables.planwide.results' => 'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report'},
       {'COMPOSITE::coreo_uni_util_variables.planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_violations'},
       {'COMPOSITE::coreo_uni_util_variables.planwide.composite_name' => 'PLAN::stack_name'},
       {'COMPOSITE::coreo_uni_util_variables.planwide.plan_name' => 'PLAN::name'}
      ])
end

# TODO: plan vars for team (name/id) and cloud account (name/id)

#list of available plan variables
# run_id
# revision
# branch
# id
# name
# stack_name
# region

coreo_uni_util_jsrunner "update-planwide-2" do
  action :run
  json_input '{}'
  function <<-EOH
    var num_advisor_violations = "COMPOSITE::coreo_uni_util_variables.planwide.number_violations";
    if (num_advisor_violations > 0) {
      coreoExport(COMPOSITE::coreo_uni_util_variables.planwide.audit_result, 'violations');
    } else {
    }
    callback();
  EOH
end

# coreo_uni_util_jsrunner "simulate-error-1" do
#   action :run
#   json_input '{}'
#   function <<-EOH
#     \\
#     \\
#     callback();
#   EOH
# end

coreo_uni_util_jsrunner "cloudtrail-aggregate" do
  action :run
  json_input '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations":COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report}'
  function <<-EOH
const alertArrayJSON = "${AUDIT_AWS_CLOUDTRAIL_REGIONS}";
const regionArrayJSON = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";



const alertArray = JSON.parse(alertArrayJSON.replace(/'/g, '"'));
const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'));

let counterForGlobalViolation = 0;
let violationCounter = 0;

function createJSONInputWithNoGlobalTrails() {
    copyViolationInNewJsonInput();
    createNoGlobalTrailViolation();
    copyPropForNewJsonInput();
}

function copyPropForNewJsonInput() {
    newJSONInput['composite name'] = json_input['composite name'];
    newJSONInput['plan name'] = json_input['plan name'];
    newJSONInput['regions'] = regionArrayJSON;
    newJSONInput['number_of_violations'] = violationCounter;
}

function copyViolationInNewJsonInput() {
    newJSONInput['violations'] = {};
    const regionKeys = Object.keys(json_input['violations']);
    regionKeys.forEach(regionKey => {
        newJSONInput['violations'][regionKey] = {};
        const objectIdKeys = Object.keys(json_input['violations'][regionKey]);
        objectIdKeys.forEach(objectIdKey => {
            const hasCloudtrailWithGlobal = json_input['violations'][regionKey][objectIdKey]['violations']['cloudtrail-trail-with-global'];
            if (hasCloudtrailWithGlobal) {
                counterForGlobalViolation++;
            } else {
                violationCounter++;
                newJSONInput['violations'][regionKey][objectIdKey] = json_input['violations'][regionKey][objectIdKey];
            }
        });
    });
}

function createNoGlobalTrailViolation() {
    const hasCloudtrailNoGlobalInAlertArray = alertArray.indexOf('cloudtrail-no-global-trails') >= 0;
    if (counterForGlobalViolation && hasCloudtrailNoGlobalInAlertArray) {
        regionArray.forEach(region => {
            violationCounter++;
            const noGlobalsMetadata = {
                'service': 'cloudtrail',
                'link': 'http://kb.cloudcoreo.com/mydoc_cloudtrail-trail-with-global.html',
                'display_name': 'Cloudtrail global logging is disabled',
                'description': 'CloudTrail global service logging is not enabled for the selected regions.',
                'category': 'Audit',
                'suggested_action': 'Enable CloudTrail global service logging in at least one region',
                'level': 'Warning',
                'region': region
            };
            const noGlobalsAlert = {
                violations: {'no-global-trails': noGlobalsMetadata },
                tags: []
            };
            setValueForNewJSONInput(region, noGlobalsMetadata, noGlobalsAlert);
        });
    }
}

function setValueForNewJSONInput(region, noGlobalsMetadata, noGlobalsAlert) {
    const regionKeys = Object.keys(newJSONInput['violations'][region]);
    regionKeys.forEach(regionKey => {
        if (newJSONInput['violations'][regionKey]) {
            if (newJSONInput['violations'][regionKey][region]) {
                newJSONInput['violations'][regionKey][region]['violations']['no-global-trails'] = noGlobalsMetadata;
            } else {
                newJSONInput['violations'][regionKey][region] = noGlobalsAlert;
            }
        }
    });
}


const newJSONInput = {};

createJSONInputWithNoGlobalTrails();

callback(newJSONInput['violations']);
  EOH
end

coreo_uni_util_variables "cloudtrail-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'}
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
  function createViolationWithSuppression(result) {
      const regionKeys = Object.keys(violations);
      regionKeys.forEach(regionKey => {
          result[regionKey] = {};
          const objectIdKeys = Object.keys(violations[regionKey]);
          objectIdKeys.forEach(objectIdKey => {
              createObjectId(regionKey, objectIdKey);
          });
      });
  }
  
  function createObjectId(regionKey, objectIdKey) {
      const wayToResultObjectId = result[regionKey][objectIdKey] = {};
      const wayToViolationObjectId = violations[regionKey][objectIdKey];
      wayToResultObjectId.tags = wayToViolationObjectId.tags;
      wayToResultObjectId.violations = {};
      createSuppression(wayToViolationObjectId, regionKey, objectIdKey);
  }
  
  
  function createSuppression(wayToViolationObjectId, regionKey, violationObjectIdKey) {
      const ruleKeys = Object.keys(wayToViolationObjectId['violations']);
      ruleKeys.forEach(violationRuleKey => {
          result[regionKey][violationObjectIdKey].violations[violationRuleKey] = wayToViolationObjectId['violations'][violationRuleKey];
          Object.keys(suppression).forEach(suppressRuleKey => {
              suppression[suppressRuleKey].forEach(suppressionObject => {
                  Object.keys(suppressionObject).forEach(suppressObjectIdKey => {
                      setDateForSuppression(
                          suppressionObject, suppressObjectIdKey,
                          violationRuleKey, suppressRuleKey,
                          violationObjectIdKey, regionKey
                      );
                  });
              });
          });
      });
  }
  
  
  function setDateForSuppression(
      suppressionObject, suppressObjectIdKey,
      violationRuleKey, suppressRuleKey,
      violationObjectIdKey, regionKey
  ) {
      file_date = null;
      let suppressDate = suppressionObject[suppressObjectIdKey];
      const areViolationsEqual = violationRuleKey === suppressRuleKey && violationObjectIdKey === suppressObjectIdKey;
      if (areViolationsEqual) {
          const nowDate = new Date();
          const correctDateSuppress = getCorrectSuppressDate(suppressDate);
          const isSuppressionDate = nowDate <= correctDateSuppress;
          if (isSuppressionDate) {
              setSuppressionProp(regionKey, violationObjectIdKey, violationRuleKey, file_date);
          } else {
              setSuppressionExpired(regionKey, violationObjectIdKey, violationRuleKey, file_date);
          }
      }
  }
  
  
  function getCorrectSuppressDate(suppressDate) {
      const hasSuppressionDate = suppressDate !== '';
      if (hasSuppressionDate) {
          file_date = suppressDate;
      } else {
          suppressDate = new Date();
      }
      let correctDateSuppress = new Date(suppressDate);
      if (isNaN(correctDateSuppress.getTime())) {
          correctDateSuppress = new Date(0);
      }
      return correctDateSuppress;
  }
  
  
  function setSuppressionProp(regionKey, objectIdKey, violationRuleKey, file_date) {
      const wayToViolationObject = result[regionKey][objectIdKey].violations[violationRuleKey];
      wayToViolationObject["suppressed"] = true;
      if (file_date != null) {
          wayToViolationObject["suppression_until"] = file_date;
          wayToViolationObject["suppression_expired"] = false;
      }
  }
  
  function setSuppressionExpired(regionKey, objectIdKey, violationRuleKey, file_date) {
      if (file_date !== null) {
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_until"] = file_date;
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_expired"] = true;
      } else {
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_expired"] = false;
      }
      result[regionKey][objectIdKey].violations[violationRuleKey]["suppressed"] = false;
  }
  
  const violations = json_input['violations'];
  const result = {};
  createViolationWithSuppression(result, json_input);
  callback(result);
  EOH
end

coreo_uni_util_jsrunner "cloudtrail-form-advisor-rule-list" do
  action :run
  json_input '{"test": "test"}'
  function <<-EOH
    var user_specified_rules = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";
    user_specified_rules = user_specified_rules.replace(/\\]/, ",'cloudtrail-trail-with-global']");
    coreoExport('rule_list_for_advisor', user_specified_rules);
    callback();
  EOH
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
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end


coreo_uni_util_jsrunner "jsrunner-process-alert-list-cloudtrail" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    let alertListToJSON = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";
    let alertListArray = alertListToJSON.replace(/'/g, '"');
    callback(alertListArray);
  EOH
end

coreo_uni_util_jsrunner "cloudtrail-tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "cloudcoreo-jsrunner-commons",
          :version => "1.8.0"
        }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "alert list": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-alert-list-cloudtrail.return,
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

coreo_uni_util_jsrunner "cloudtrail-notifier-actions" do
  action :run
  json_input '{}'
  function <<-EOH

    var AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT = "${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}";
    var AUDIT_AWS_CLOUDTRAIL_OWNER_TAG = "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}";

    var action_html = ':nothing';
    var action_rollup = ':nothing';

    if (AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT.length > 0) {
      action_html = ":notify";
      if (! AUDIT_AWS_CLOUDTRAIL_OWNER_TAG === "NOT_A_TAG") {
        action_rollup = ':notify';
      }
    }

    coreoExport('AUDIT_AWS_CLOUDTRAIL_HTML_REPORT', action_html);
    coreoExport('AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT', action_rollup);

    callback();
  EOH
end

coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :${AUDIT_AWS_CLOUDTRAIL_HTML_REPORT}
  #action(((${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}.length > 0) and (! ${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}.eql?("NOT_A_TAG"))) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-cloudtrail-rollup" do
  #action :${AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT}
  #action COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-notifier-actions.AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT
  action(((${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}.length > 0) and (! ${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}.eql?("NOT_A_TAG"))) ? :notify : :nothing)
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
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'PLAN::stack_name New Rollup Report for PLAN::name plan from CloudCoreo'
  })
end

# PLAN::stack_name New Rollup Report for PLAN::name plan from CloudCoreo