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
  description "Gather raw data for regions with global service events enabled. There should be at least one."
  category "Audit"
  suggested_action "Enable global service event logging on at least one Trail"
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

coreo_aws_advisor_cloudtrail "trail-with-global" do
  alerts ["trail-with-global"]
  action :advise
end

# This resource will postprocess trail-with-global to generate an alert result
# if there are no regions that log global service events. Best practice is
# to have at least one region that logs global services events.
coreo_uni_util_jsrunner "cloudtrail-aggregate" do
  action :run
  json_input 'STACK::coreo_aws_advisor_cloudtrail.trail-with-global.report'
  function <<-EOH
var result;
console.log(util.inspect(json_input, {showHidden: false, depth: null}));

var nRegionsWithGlobal = Object.keys(input).length;
console.log('Number of regions with global: ' + nRegionsWithGlobal);

if (nRegionsWithGlobal == 0) {
  result = { 'all-regions':  { violations:
            { 'no-global-trails':
               { description: 'this is a alert to run',
                 category: 'vulnerablity',
                 suggested_action: 'fix it',
                 level: 'warning',
                 region: 'all-regions' } },
           tags: [] } };
  console.log(result);
} else {
  result = {};
  console.log('there is at least one region with global service enabled');
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
  "violations": STACK::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report }'
  payload_type "${AUDIT_AWS_CLOUDTRAIL_PAYLOAD_TYPE}"
  endpoint ({ 
              :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
            })
end
