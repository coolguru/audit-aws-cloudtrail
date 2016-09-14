# service-disabled

coreo_aws_advisor_alert "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
#  display_name "AWS CloudTrail Service Disabled"
#  uuid "BD9BA1AE-2555-4407-8618-B6B188A33CE2"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs"
  level "Warning"
  link "http://kb.cloudcoreo.com/descriptions/cloudtrail-service-disabled.txt"
  objectives ["trails"]
  formulas ["count"]
  audit_objects ["trail_list"]
  operators ["=="]
  alert_when [0]
end

coreo_aws_advisor_cloudtrail "advise-cloudtrail" do
  alerts ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}
  regions ${AUDIT_AWS_CLOUDTRAIL_REGIONS}
  action :advise
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
