import {
  createTestIntegrationData,
  createTestIntegrationExecutionContext,
} from "@jupiterone/jupiter-managed-integration-sdk";
import mockWhitehatClient from "../test/helpers/mockWhitehatClient";
import synchronize from "./synchronize";

jest.mock("@jupiterone/whitehat-client", () => {
  return jest.fn().mockImplementation(() => mockWhitehatClient);
});

const persisterOperations = {
  created: 1,
  deleted: 0,
  updated: 0,
};

const executionContext = createTestIntegrationExecutionContext();
const { job: mockIntegrationJob } = createTestIntegrationData();

executionContext.instance.config = {
  veracodeApiId: "some-id",
  veracodeApiSecret: "some-secret",
};

jest
  .spyOn(executionContext.clients.getClients().graph, "findEntities")
  .mockResolvedValue([]);

jest
  .spyOn(executionContext.clients.getClients().graph, "findRelationships")
  .mockResolvedValue([]);

jest
  .spyOn(
    executionContext.clients.getClients().persister,
    "publishPersisterOperations",
  )
  .mockResolvedValue(persisterOperations);

test("compiles and runs", async () => {
  const result = await synchronize(executionContext);

  expect(mockWhitehatClient.getVulnerabilities).toHaveBeenCalledWith({
    queryParams: ["query_status=open,closed"],
  });
  expect(result).toEqual(persisterOperations);
});

test("uses last job created date for provider queries", async () => {
  jest
    .spyOn(executionContext.clients.getClients().jobs, "getLastCompleted")
    .mockResolvedValue(mockIntegrationJob);

  const result = await synchronize(executionContext);
  const mockCreateDate = new Date(mockIntegrationJob.createDate).toISOString();

  expect(mockWhitehatClient.getVulnerabilities).toHaveBeenCalledWith({
    queryParams: [
      "query_status=open,closed",
      `query_opened_after=${mockCreateDate}`,
      `query_closed_after=${mockCreateDate}`,
      `query_found_after=${mockCreateDate}`,
    ],
  });
  expect(result).toEqual(persisterOperations);
});
