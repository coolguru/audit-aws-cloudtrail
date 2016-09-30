# service-disabled

coreo_aws_advisor_alert "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
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

coreo_aws_advisor_alert "trail-with-global" do
  action :define
  service :cloudtrail
  level "Warning"
  objectives ["trails"]
  audit_objects ["trail_list.include_global_service_events"]
  operators ["=="]
  alert_when [true]
  id_map "object.trail_list.name"
end

coreo_aws_advisor_cloudtrail "advise-cloudtrail" do
  alerts ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}
  regions ${AUDIT_AWS_CLOUDTRAIL_REGIONS}
  action :advise
end

# This resource will postprocess trail-with-global to generate an alert result
# if there are no regions that log global service events. Best practice is
# to have at least one region that logs global services events.
coreo_uni_util_jsrunner "cloudtrail-aggregate" do
  action :run
  json_input 'STACK::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report'
  function <<-EOH
var result = {};
console.log(util.inspect(json_input, {showHidden: false, depth: null}));

var nRegionsWithGlobal = 0;
for (var key in json_input) {
  if (json_input.hasOwnProperty(key)) {
    console.log('checking key: ' + key);
    if (json_input[key]['violations']['trail-with-global']) {
      console.log("Trail has a region with global: " + key);
      nRegionsWithGlobal++;
    } else {
      result[key] = json_input[key];
    }
  }
}
console.log('Number of regions with global: ' + nRegionsWithGlobal);

var noGlobalsAlert = {};
if (nRegionsWithGlobal == 0) {
  noGlobalsAlert = { violations:
            { 'no-global-trails':
               { description: 'CloudTrail global service logging is not enabled for the selected regions.',
                 category: 'Audit',
                 suggested_action: 'Enable CloudTrail global service logging in at least one region',
                 level: 'Warning',
                 region: 'selected-regions' } },
           tags: [] };
  result['selected-regions'] = noGlobalsAlert;
}

callback(result);
EOH
end

coreo_uni_util_notify "advise-cloudtrail" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"STACK::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"STACK::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations": STACK::coreo_uni_util_jsrunner.cloudtrail-aggregate.return }'
  payload_type "${AUDIT_AWS_CLOUDTRAIL_PAYLOAD_TYPE}"
  endpoint ({ 
              :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
            })
end
