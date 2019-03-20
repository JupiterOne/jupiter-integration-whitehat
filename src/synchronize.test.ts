import { createTestIntegrationExecutionContext } from "@jupiterone/jupiter-managed-integration-sdk";
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

test("compiles and runs", async () => {
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

  const result = await synchronize(executionContext);
  expect(result).toEqual(persisterOperations);
});
