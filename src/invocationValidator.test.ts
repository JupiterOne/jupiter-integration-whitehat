import { createTestIntegrationExecutionContext } from "@jupiterone/jupiter-managed-integration-sdk";
import invocationValidator from "./invocationValidator";
import { WhitehatIntegrationInstanceConfig } from "./types";

test("passes with valid config", async () => {
  const config: WhitehatIntegrationInstanceConfig = {
    whitehatApiKey: "api-key",
  };

  const executionContext = createTestIntegrationExecutionContext({
    instance: {
      config,
    },
  });

  expect(() => {
    invocationValidator(executionContext);
  }).not.toThrow();
});

test("throws error if config not provided", async () => {
  const executionContext = createTestIntegrationExecutionContext();
  await expect(invocationValidator(executionContext)).rejects.toThrow(
    "Missing configuration",
  );
});

test("throws error if API id and secret are not provided in instance config", async () => {
  const executionContext = createTestIntegrationExecutionContext({
    instance: {
      config: {},
    },
  });
  await expect(invocationValidator(executionContext)).rejects.toThrow(
    "whitehatApiKey is required",
  );
});
