import {
  createTestIntegrationExecutionContext,
  IntegrationInstanceAuthenticationError,
} from "@jupiterone/jupiter-managed-integration-sdk";
import mockWhitehatClient from "../test/helpers/mockWhitehatClient";
import invocationValidator from "./invocationValidator";
import { WhitehatIntegrationInstanceConfig } from "./types";

jest.mock("@jupiterone/whitehat-client", () => {
  return jest.fn().mockImplementation(() => mockWhitehatClient);
});

const validConfig: WhitehatIntegrationInstanceConfig = {
  whitehatApiKey: "api-key",
};

test("passes with valid config", async () => {
  const executionContext = createTestIntegrationExecutionContext({
    instance: {
      config: validConfig,
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

test("throws error if API key is not provided in instance config", async () => {
  const executionContext = createTestIntegrationExecutionContext({
    instance: {
      config: {},
    },
  });
  await expect(invocationValidator(executionContext)).rejects.toThrow(
    "whitehatApiKey is required",
  );
});

test("throws error if Whitehat responds with error to resource call", async () => {
  const executionContext = createTestIntegrationExecutionContext({
    instance: {
      config: validConfig,
    },
  });

  mockWhitehatClient.getResources = jest.fn().mockImplementation(() => {
    throw new Error("401");
  });

  await expect(invocationValidator(executionContext)).rejects.toThrow(
    IntegrationInstanceAuthenticationError,
  );
});
