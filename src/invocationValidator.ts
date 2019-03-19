import {
  IntegrationExecutionContext,
  IntegrationInstanceConfigError,
  IntegrationInvocationEvent,
} from "@jupiterone/jupiter-managed-integration-sdk";
import { WhitehatIntegrationInstanceConfig } from "./types";

export default async function invocationValidator(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
) {
  const config = context.instance.config as WhitehatIntegrationInstanceConfig;
  if (!config) {
    throw new IntegrationInstanceConfigError("Missing configuration");
  } else if (!config.whitehatApiKey) {
    throw new IntegrationInstanceConfigError("whitehatApiKey is required");
  }
}
