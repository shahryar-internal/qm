import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const layerDirectory = fileURLToPath(new URL("../../", import.meta.url));
const read = (path) => readFileSync(`${layerDirectory}${path}`, "utf8");
const broker = read("infra/ceo-canary-db-inventory-broker.tf");
const main = read("infra/main.tf");
const outputs = read("infra/outputs.tf");

test("inventory broker can launch only the exact read-only task with no caller overrides", () => {
  assert.match(broker, /phase\s+= "inventory"/);
  assert.match(broker, /readOnly\s+= true/);
  assert.match(broker, /TaskDefinition\s+= aws_ecs_task_definition\.ceo_canary_db_operator\["inventory"\]\.arn/);
  assert.match(broker, /InputPath\s+= null/);
  assert.match(broker, /LaunchType\s+= "FARGATE"/);
  assert.match(broker, /PlatformVersion\s+= "1\.4\.0"/);
  assert.match(broker, /EnableExecuteCommand = false/);
  assert.match(broker, /AssignPublicIp = "DISABLED"/);
  assert.match(broker, /SecurityGroups = \[aws_security_group\.ceo_canary\.id\]/);
  assert.doesNotMatch(broker, /^\s+Overrides\s+=/m);
  assert.doesNotMatch(broker, /^\s+Command\s+=/m);
  assert.doesNotMatch(broker, /^\s+Environment\s+=/m);
  assert.doesNotMatch(broker, /^\s+TaskRoleArn\s+=/m);
  assert.doesNotMatch(broker, /^\s+ExecutionRoleArn\s+=/m);
  assert.doesNotMatch(broker, /^\s+Count\s+=/m);
  assert.doesNotMatch(broker, /^\s+StartedBy\s+=/m);
  assert.doesNotMatch(broker, /bootstrap|provision|migrate|readiness/);
});

test("broker execution role is source-bound and cannot pass unrelated roles", () => {
  assert.match(broker, /Service = "states\.amazonaws\.com"/);
  assert.match(broker, /"aws:SourceArn" = local\.ceo_canary_db_inventory_broker_arn/);
  assert.match(broker, /"aws:SourceAccount" = var\.account_id/);
  assert.match(broker, /Resource = aws_ecs_task_definition\.ceo_canary_db_operator\["inventory"\]\.arn/);
  assert.match(broker, /"ecs:cluster"\s+= aws_ecs_cluster\.this\.arn/);
  assert.match(broker, /Bool = \{\s*"ecs:auto-assign-public-ip" = "false"/);
  assert.match(broker, /StringEquals = \{\s*"ecs:enable-execute-command" = "false"/);
  assert.match(broker, /Null = \{\s*"ecs:subnet" = "false"/);
  assert.match(broker, /aws_iam_role\.ceo_canary_db_operator_task\["inventory"\]\.arn/);
  assert.match(broker, /aws_iam_role\.ceo_canary_db_operator_execution\["inventory"\]\.arn/);
  assert.match(broker, /"iam:PassedToService" = "ecs-tasks\.amazonaws\.com"/);
  assert.doesNotMatch(broker, /states:StartExecution/);
  assert.doesNotMatch(broker, /Principal\s+= \{\s*AWS/);
  assert.doesNotMatch(main, /states:(?:StartExecution|UpdateStateMachine|DeleteStateMachine|\*)/);
});

test("broker is absent with the operator and has no automatic execution path", () => {
  for (const resource of ["aws_iam_role", "aws_iam_role_policy", "aws_sfn_state_machine"]) {
    assert.match(
      broker,
      new RegExp(
        `resource "${resource}" "ceo_canary_db_inventory_broker" \\{[\\s\\S]*?count\\s*= local\\.ceo_canary_db_inventory_broker_enabled \\? 1 : 0`,
      ),
    );
  }
  assert.match(broker, /automaticStart\s+= false/);
  assert.match(broker, /invokerRoleCreated\s+= false/);
  assert.doesNotMatch(broker, /aws_scheduler|aws_cloudwatch_event|aws_lambda|aws_ecs_service/);
  assert.match(outputs, /output "ceo_canary_db_inventory_broker_provenance"/);
  assert.match(outputs, /stateMachineArn\s+= aws_sfn_state_machine\.ceo_canary_db_inventory_broker\[0\]\.arn/);
});
