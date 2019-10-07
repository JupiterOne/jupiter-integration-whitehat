import {
  IntegrationExecutionContext,
  PersisterOperationsResult,
} from "@jupiterone/jupiter-managed-integration-sdk";
import WhitehatClient from "@jupiterone/whitehat-client";

import { DEFAULT_SERVICE_ENTITY_MAP } from "./constants";
import {
  FindingData,
  toAccountEntity,
  toCVEEntities,
  toFindingEntity,
  toVulnerabilityEntity,
} from "./converters";
import {
  createOperationsFromAccount,
  createOperationsFromFindings,
} from "./createOperations";
import {
  CVEEntityMap,
  FindingEntityMap,
  ServiceEntityMap,
  VulnerabilityEntity,
  VulnerabilityEntityMap,
  WhitehatIntegrationInstanceConfig,
} from "./types";
import getLastSyncTime from "./utils/getLastSyncTime";

interface ProcessFindingsResults {
  vulnerabilities: VulnerabilityEntity[];

  cveMap: CVEEntityMap;
  findingMap: FindingEntityMap;
  serviceMap: ServiceEntityMap;
}

async function getFindings(
  context: IntegrationExecutionContext,
  whitehatClient: any,
): Promise<FindingData[]> {
  const queryParams = ["query_status=open,closed"];

  const lastSyncTime = await getLastSyncTime(context);
  if (lastSyncTime) {
    const lastJobCreatedDate = new Date(lastSyncTime).toISOString();
    queryParams.push(
      `query_opened_after=${lastJobCreatedDate}`,
      `query_closed_after=${lastJobCreatedDate}`,
      `query_found_after=${lastJobCreatedDate}`,
    );
  }

  return await whitehatClient.getVulnerabilities({
    queryParams,
  });
}

function processFindings(findings: FindingData[]): ProcessFindingsResults {
  const cveMap: CVEEntityMap = {};
  const vulnerabilityMap: VulnerabilityEntityMap = {};
  const serviceMap: ServiceEntityMap = DEFAULT_SERVICE_ENTITY_MAP;
  const findingMap: FindingEntityMap = {};

  for (const finding of findings) {
    const vulnerability = toVulnerabilityEntity(finding);
    const existingVulnerability = vulnerabilityMap[finding.class];

    // For a given finding class, the only differentiator between resulting
    // vulnerabilities should be createdOn. We want to keep the older createdOn
    // because a vulnerability's createdOn should be the date of the earliest
    // finding of the vulnerability.
    if (
      !existingVulnerability ||
      (existingVulnerability &&
        existingVulnerability.createdOn > vulnerability.createdOn)
    ) {
      vulnerabilityMap[finding.class] = vulnerability;
    }

    cveMap[finding.class] = toCVEEntities(finding);

    findingMap[finding.class] = findingMap[finding.class] || [];
    findingMap[finding.class].push(toFindingEntity(finding));
  }

  return {
    vulnerabilities: Object.values(vulnerabilityMap),

    cveMap,
    findingMap,
    serviceMap,
  };
}

export default async function synchronize(
  context: IntegrationExecutionContext,
): Promise<PersisterOperationsResult> {
  const { persister } = context.clients.getClients();
  const config = context.instance.config as WhitehatIntegrationInstanceConfig;
  const whitehatClient = new WhitehatClient(config.whitehatApiKey);

  const account = toAccountEntity(
    (await whitehatClient.getResources()).account,
    context.instance,
  );

  const { vulnerabilities, cveMap, serviceMap, findingMap } = processFindings(
    await getFindings(context, whitehatClient),
  );

  return persister.publishPersisterOperations(
    await createOperationsFromAccount(context, account),
    await createOperationsFromFindings(
      context,
      account,
      vulnerabilities,
      cveMap,
      serviceMap,
      findingMap,
    ),
  );
}
