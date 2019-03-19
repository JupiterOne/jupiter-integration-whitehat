import {
  IntegrationExecutionContext,
  IntegrationExecutionResult,
  IntegrationInvocationEvent,
} from "@jupiterone/jupiter-managed-integration-sdk";
import synchronize from "./synchronize";

export default async function executionHandler(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
): Promise<IntegrationExecutionResult> {
  return { operations: await synchronize(context) };
}
