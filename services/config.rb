# service-disabled

coreo_aws_advisor_alert "cloudtrail-inventory" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_inventory.html"
  include_violations_in_count false
  display_name "CloudTrail Inventory"
  description "This rule performs an inventory on all CloudTrails in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["trails"]
  audit_objects ["trail_list.name"]
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
end

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
end

coreo_aws_advisor_alert "no-global-trails" do
  action :define
  service :cloudtrail
  category "jsrunner"
  suggested_action "The metadata for this definition is defined in the jsrunner below. Do not put metadata here."
  level "jsrunner"
  objectives [""]
  audit_objects [""]
  operators [""]
  alert_when [true]
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
  regionArray.forEach(region => {
    nViolations++;
    noGlobalsMetadata =
    {
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
              { 'no-global-trails':
              noGlobalsMetadata
              },
              tags: []
            };
    var key = 'selected regions';
    console.log('saving global violation on key: ' + key + ' | violation: ' + JSON.stringify(noGlobalsAlert));
    if (result['violations'][region]) {
        result['violations'][region]['violations']['no-global-trails'] = noGlobalsMetadata;
    } else {
        result['violations'][region] = noGlobalsAlert;
    }
  });

}

console.log('Number of violations: ' + nViolations);
result['number_of_violations'] = nViolations;
callback(result);
  EOH
end

coreo_uni_util_jsrunner "jsrunner-process-suppressions" do
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

// Get document, or throw exception on error
    try {
        var suppressions = yaml.safeLoad(fs.readFileSync('./suppressions.yaml', 'utf8'));
        console.log(suppressions);
    } catch (e) {
        console.log(e);
    }

    var result = {};
    result["composite name"] = json_input["composite name"];
    result["number_of_violations"] = json_input["number_of_violations"];
    result["plan name"] = json_input["plan name"];
    result["regions"] = json_input["regions"];
    result["violations"] = {};

    for (var violator_id in json_input.violations) {
        result["violations"][violator_id] = {};
        result["violations"][violator_id].tags = json_input.violations[violator_id].tags;
        result["violations"][violator_id].violations = {}
        //console.log(violator_id);
        for (var rule_id in json_input.violations[violator_id].violations) {
            console.log("object " + violator_id + " violates rule " + rule_id);
            is_violation = true;
            for (var suppress_rule_id in suppressions["suppressions"]) {
                for (var suppress_violator_id in suppressions["suppressions"][suppress_rule_id]) {
                    var suppress_obj_id = suppressions["suppressions"][suppress_rule_id][suppress_violator_id];
                    console.log(" compare: " + rule_id + ":" + violator_id + " <> " + suppress_rule_id + ":" + suppress_obj_id);
                    if (rule_id === suppress_rule_id) {
                        console.log("    have a suppression for rule: " + rule_id);
                        if (violator_id === suppress_obj_id) {
                            console.log("    *** found violation to suppress: " + suppress_obj_id);
                            is_violation = false;
                        }
                    }
                }
            }
            if (is_violation) {
                console.log("    +++ not suppressed - including in results");
                result["violations"][violator_id].violations[rule_id] = json_input.violations[violator_id].violations[rule_id];
            }
        }
    }

    var rtn = result;

    callback(result);


EOH
end

coreo_uni_util_jsrunner "jsrunner-output-table" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH

    Object.byString = function(o, s) {
    s = s.replace(/\[(w+)\]/g, '.$1'); // convert indexes to properties
    s = s.replace(/^\./, '');           // strip a leading dot
    var a = s.split('.');
    for (var i = 0, n = a.length; i < n; ++i) {
        var k = a[i];
        if (k in o) {
            o = o[k];
        } else {
            return;
        }
    }
    return o;
    }

    var fs = require('fs');
    var yaml = require('js-yaml');

// Get document, or throw exception on error
    try {
        var tables = yaml.safeLoad(fs.readFileSync('./tables.yaml', 'utf8'));
        console.log(tables);
    } catch (e) {
        console.log(e);
    }

    var result = {};

    for (var violator_id in json_input.violations) {
        for (var rule_id in json_input.violations[violator_id].violations) {
            console.log("object " + violator_id + " violates rule " + rule_id);
            if (result[rule_id]) {
            } else {
                result[rule_id] = {};
                result[rule_id]["header"] = "";
                result[rule_id]["nrows"] = 0;
                result[rule_id]["rows"] = {};
            }
            for (var table_rule_id in tables) {
                //console.log(table_rule_id);
                if (rule_id === table_rule_id) {
                    //console.log("found a table entry for rule: " + rule_id);
                    var col_num = 0;
                    var col_num_str = col_num.toString();
                    var this_row = "";
                    for (var table_entry in tables[table_rule_id]) {
                        console.log("  " + table_entry + " is " + tables[table_rule_id][table_entry]);
                        var indx = result[rule_id]["header"].indexOf(table_entry);
                        if (result[rule_id]["header"].indexOf(table_entry) === -1) {
                            result[rule_id]["header"] = result[rule_id]["header"] + "," + table_entry;
                        }
                        var resolved_entry = tables[table_rule_id][table_entry];
                        var re = /__OBJECT__/gi;
                        resolved_entry = resolved_entry.replace(re, violator_id);
                        re = /__RULE__/gi;
                        resolved_entry = resolved_entry.replace(re, rule_id);

                        var tags = null;
                        tags = json_input.violations[violator_id].tags;
                        
                        re = /\+([^+]+)\+/;
                        var match;
                        while (match = re.exec(resolved_entry)) {
                            console.log(match);
                            var to_resolve = match[1];
                            var resolved = Object.byString(json_input.violations, to_resolve);
                            if (resolved && resolved.match(/arn:aws/)) {
                                resolved = resolved.replace("/", "@");
                            }
                            resolved_entry = resolved_entry.replace(match[0], resolved);

                        }
                        if (!result[rule_id]["rows"][col_num]) {
                            result[rule_id]["rows"][col_num] = {};
                        }
                        this_row = this_row + "," + resolved_entry;

                        col_num++;
                        col_num_str = col_num.toString();

                    }
                    result[rule_id]["header"] = result[rule_id]["header"].replace(/^,/, "");

                    var row_num = result[rule_id]["nrows"];
                    var row_num_str = row_num.toString();


                    this_row = this_row.replace(/^,/, "");
                    result[rule_id]["rows"][row_num_str] = this_row;

                    result[rule_id]["nrows"]++;
                }
            }
        }
    }

    var rtn = result;

    callback(result);


EOH
end

coreo_uni_util_variables "update-advisor-output" do
  action :set
  variables([
       {'COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return.violations'}
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
          :version => "1.3.9"
        }       ])
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return'
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
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

