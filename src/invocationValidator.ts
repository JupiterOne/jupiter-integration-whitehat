import {
  IntegrationExecutionContext,
  IntegrationInstanceAuthenticationError,
  IntegrationInstanceConfigError,
  IntegrationInvocationEvent,
} from "@jupiterone/jupiter-managed-integration-sdk";
import WhitehatClient from "@jupiterone/whitehat-client";
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

  const provider = new WhitehatClient(config.whitehatApiKey);
  try {
    // Attempt to fetch the types of resources accessible using the given API
    // key. If there's any error, the API key is invalid.
    await provider.getResources();
  } catch (err) {
    throw new IntegrationInstanceAuthenticationError(err);
  }
}
