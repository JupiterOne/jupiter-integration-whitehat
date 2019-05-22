import { createTestIntegrationExecutionContext } from "@jupiterone/jupiter-managed-integration-sdk";

import mockWhitehatClient from "../test/helpers/mockWhitehatClient";
import synchronize from "./synchronize";
import getLastSyncTime from "./utils/getLastSyncTime";

jest.mock("@jupiterone/whitehat-client", () => {
  return jest.fn().mockImplementation(() => mockWhitehatClient);
});

const persisterOperations = {
  created: 1,
  deleted: 0,
  updated: 0,
};

const executionContext = createTestIntegrationExecutionContext();

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

jest.mock("./utils/getLastSyncTime");

test("compiles and runs", async () => {
  const result = await synchronize(executionContext);

  expect(mockWhitehatClient.getVulnerabilities).toHaveBeenCalledWith({
    queryParams: ["query_status=open,closed"],
  });
  expect(result).toEqual(persisterOperations);
});

test("provider queries", async () => {
  (getLastSyncTime as jest.Mock).mockResolvedValue(null);

  const result = await synchronize(executionContext);

  expect(mockWhitehatClient.getVulnerabilities).toHaveBeenCalledWith({
    queryParams: ["query_status=open,closed"],
  });
  expect(result).toEqual(persisterOperations);
});

test("uses last synchronization time for provider queries", async () => {
  (getLastSyncTime as jest.Mock).mockResolvedValue(1558533852128);

  const result = await synchronize(executionContext);

  expect(mockWhitehatClient.getVulnerabilities).toHaveBeenCalledWith({
    queryParams: [
      "query_status=open,closed",
      `query_opened_after=2019-05-22T14:04:12.128Z`,
      `query_closed_after=2019-05-22T14:04:12.128Z`,
      `query_found_after=2019-05-22T14:04:12.128Z`,
    ],
  });
  expect(result).toEqual(persisterOperations);
});
