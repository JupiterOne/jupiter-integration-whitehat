import {
  IntegrationInstanceAuthenticationError,
  IntegrationInstanceConfigError,
  IntegrationValidationContext,
} from "@jupiterone/jupiter-managed-integration-sdk";
import WhitehatClient from "@jupiterone/whitehat-client";

import { WhitehatIntegrationInstanceConfig } from "./types";

/**
 * Performs validation of the execution before the execution handler function is
 * invoked.
 *
 * At a minimum, integrations should ensure that the
 * `context.instance.config` is valid. Integrations that require
 * additional information in `context.invocationArgs` should also
 * validate those properties. It is also helpful to perform authentication with
 * the provider to ensure that credentials are valid.
 *
 * The function will be awaited to support connecting to the provider for this
 * purpose.
 *
 * @param context
 */
export default async function invocationValidator(
  context: IntegrationValidationContext,
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
