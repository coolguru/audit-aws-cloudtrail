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
  level "Information"
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

# This resource will postprocess cloudtrail-trail-with-global to generate an alert result
# if there are no regions that log global service events. Best practice is
# to have at least one region that logs global services events.
coreo_uni_util_jsrunner "cloudtrail-aggregate" do
  action :run
  json_input '{"stack name":"PLAN::stack_name",
  "instance name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations":COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report}'
  function <<-EOH
var_regions = "${AUDIT_AWS_CLOUDTRAIL_REGIONS}";
var result = {};
result['stack name'] = json_input['stack name'];
result['instance name'] = json_input['instance name'];
result['regions'] = var_regions;
result['number_of_checks'] = json_input['number_of_checks'];
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
               { 'description': 'CloudTrail global service logging is not enabled for the selected regions.',
                 'category': 'Audit',
                 'suggested_action': 'Enable CloudTrail global service logging in at least one region',
                 'level': 'Warning',
                 'regions': var_regions
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

# this is the original notifier
#
# coreo_uni_util_notify "advise-cloudtrail-old" do
#   action :notify
#   type 'email'
#   allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
#   send_on "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}"
#   payload '{"stack name":"PLAN::stack_name",
#   "instance name":"PLAN::name",
#   "number_of_checks":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
#   "number_of_violations":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
#   "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations",
#   "violations": COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report }'
#   payload_type "json"
#   endpoint ({ 
#               :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
#             })
# end

# this is the new notifier that takes the violations transformed by the jsrunner
#
coreo_uni_util_notify "advise-cloudtrail" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'
  payload_type "json"
  endpoint ({ 
              :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
            })
end

#   "regions":"${AUDIT_AWS_CLOUDTRAIL_REGIONS}",
