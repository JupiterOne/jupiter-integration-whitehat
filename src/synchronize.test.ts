const findingsMock = jest.fn();
const resourcesMock = jest.fn();

jest.doMock("@jupiterone/whitehat-client", () => {
  return jest.fn().mockImplementation(() => {
    return {
      getVulnerabilities: findingsMock,
      getResources: resourcesMock,
    };
  });
});

import {
  createTestIntegrationExecutionContext,
  EntityOperation,
  EntityOperationType,
  RelationshipOperation,
} from "@jupiterone/jupiter-managed-integration-sdk";
import {
  CreateEntityOperation,
  UpdateEntityOperation,
} from "@jupiterone/jupiter-managed-integration-sdk/jupiter-types";

import { mockFinding, mockResources } from "../test/helpers/mockWhitehatClient";
import { WHITEHAT_VULNERABILITY_ENTITY_TYPE } from "./constants";
import { toVulnerabilityEntity } from "./converters";
import synchronize from "./synchronize";
import getLastSyncTime from "./utils/getLastSyncTime";

jest.mock("./utils/getLastSyncTime");

const persisterOperations = {
  created: 1,
  deleted: 0,
  updated: 0,
};

const testContext = {
  instance: {
    config: {
      veracodeApiId: "some-id",
      veracodeApiSecret: "some-secret",
    },
  },
};
const executionContext = createTestIntegrationExecutionContext(testContext);

beforeAll(() => {
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
});

beforeEach(() => {
  findingsMock.mockReset();
  resourcesMock.mockReset();
  findingsMock.mockResolvedValue([mockFinding]);
  resourcesMock.mockResolvedValue(mockResources);
});

test("compiles and runs", async () => {
  const result = await synchronize(executionContext);

  expect(findingsMock).toHaveBeenCalledWith({
    queryParams: ["query_status=open,closed"],
  });
  expect(result).toEqual(persisterOperations);
});

test("provider queries", async () => {
  (getLastSyncTime as jest.Mock).mockResolvedValue(null);

  const result = await synchronize(executionContext);

  expect(findingsMock).toHaveBeenCalledWith({
    queryParams: ["query_status=open,closed"],
  });
  expect(result).toEqual(persisterOperations);
});

test("uses last synchronization time for provider queries", async () => {
  (getLastSyncTime as jest.Mock).mockResolvedValue(1558533852128);

  const result = await synchronize(executionContext);

  expect(findingsMock).toHaveBeenCalledWith({
    queryParams: [
      "query_status=open,closed",
      `query_opened_after=2019-05-22T14:04:12.128Z`,
      `query_closed_after=2019-05-22T14:04:12.128Z`,
      `query_found_after=2019-05-22T14:04:12.128Z`,
    ],
  });
  expect(result).toEqual(persisterOperations);
});

test("vulnerability should take oldest finding date", async () => {
  const olderCreatedOn = new Date("2001-09-11T08:56:00.000Z");
  const olderFinding = { ...mockFinding };
  olderFinding.found = olderCreatedOn.toISOString();

  findingsMock.mockResolvedValue([olderFinding, mockFinding]);

  await synchronize(executionContext);

  expect(executionContext.clients.getClients().persister
    .publishPersisterOperations as jest.Mock).toBeCalledTimes(1);

  const call = (executionContext.clients.getClients().persister
    .publishPersisterOperations as jest.Mock).mock.calls[0];
  const operationsFromFindings: [EntityOperation[], RelationshipOperation[]] =
    call[1];
  const entityOperationsFromFindings = operationsFromFindings[0];
  const nonCreateOperations = entityOperationsFromFindings.filter(
    operation => operation.type !== EntityOperationType.CREATE_ENTITY,
  );

  expect(nonCreateOperations.length).toBe(0);

  const createVulnerabilityOperations = (entityOperationsFromFindings as CreateEntityOperation[]).filter(
    operation => operation.entityType === WHITEHAT_VULNERABILITY_ENTITY_TYPE,
  );

  expect(createVulnerabilityOperations.length).toBe(1);
  // Should only update displayName, since the vertex in the graph has the older
  // createdOn date.
  expect(createVulnerabilityOperations[0].properties!.createdOn).toEqual(
    olderCreatedOn.getTime(),
  );
});

test("vulnerability should keep older dates from graph", async () => {
  jest
    .spyOn(executionContext.clients.getClients().graph, "findAllEntitiesByType")
    .mockImplementation(async type => {
      if (type === WHITEHAT_VULNERABILITY_ENTITY_TYPE) {
        const existingVulnerability = toVulnerabilityEntity(mockFinding);
        const olderDate = new Date("2001-09-11T08:56:00.000Z").getTime();
        existingVulnerability.createdOn = olderDate;
        // Something other than the dates needs to be different. Otherwise, the
        // operation is not sent because processEntities detects that there are
        // no changes.
        existingVulnerability.displayName = "Kill Bill 3";
        return [existingVulnerability];
      }

      return [];
    });

  await synchronize(executionContext);

  const call = (executionContext.clients.getClients().persister
    .publishPersisterOperations as jest.Mock).mock.calls[0];
  const operationsFromFindings: [EntityOperation[], RelationshipOperation[]] =
    call[1];
  const entityOperationsFromFindings = operationsFromFindings[0];
  const updateEntityOperations = entityOperationsFromFindings.filter(
    operation => operation.type === EntityOperationType.UPDATE_ENTITY,
  ) as UpdateEntityOperation[];

  expect(updateEntityOperations.length).toBe(1);
  // Should only update displayName, since the vertex in the graph has the older
  // createdOn date.
  expect(updateEntityOperations[0].properties).toEqual({
    displayName: "My Mock Class",
  });
});
