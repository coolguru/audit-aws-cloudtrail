# service-disabled

coreo_aws_advisor_alert "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/cloudtrail-service-disabled.html"
  display_name "Cloudtrail Service is disabled"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs"
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
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["trails"]
  audit_objects ["trail_list.include_global_service_events"]
  operators ["=="]
  alert_when [true]
  id_map "object.trail_list.name"
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
result['stack name'] = json_input['stack name'];
result['instance name'] = json_input['instance name'];
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

coreo_uni_util_notify "advise-cloudtrail-json" do
  action :${AUDIT_AWS_CLOUDTRAIL_FULL_JSON_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on 'always'
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
          :version => "1.1.2"
        }       ])
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCloudtrail = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_CLOUDTRAIL_ALERT_NO_OWNER_RECIPIENT}", "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}", 'cloudtrail');
const notifiers = AuditCloudtrail.getNotifiers();
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
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
callback(rollup_string);
EOH
end


## Send Notifiers
coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :${AUDIT_AWS_CLOUDTRAIL_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
end




coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action :${AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on 'always'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_violations_ignored: COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations

rollup report:
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

