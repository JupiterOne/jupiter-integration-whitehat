import {
  IntegrationExecutionContext,
  IntegrationInvocationEvent,
  PersisterOperationsResult,
} from "@jupiterone/jupiter-managed-integration-sdk";
import JobsClient from "@jupiterone/jupiter-managed-integration-sdk/service/JobsClient";
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

interface ProcessFindingsResults {
  vulnerabilities: VulnerabilityEntity[];

  cveMap: CVEEntityMap;
  findingMap: FindingEntityMap;
  serviceMap: ServiceEntityMap;
}

async function getFindings(
  whitehatClient: any,
  jobsClient: JobsClient,
): Promise<FindingData[]> {
  const queryParams = ["query_status=open,closed"];

  const lastJob = await jobsClient.getLastCompleted();
  if (lastJob) {
    const lastJobCreatedDate = new Date(lastJob.createDate).toISOString();
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
    vulnerabilityMap[finding.class] = toVulnerabilityEntity(finding);

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
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
): Promise<PersisterOperationsResult> {
  const { persister, jobs } = context.clients.getClients();
  const config = context.instance.config as WhitehatIntegrationInstanceConfig;
  const whitehat = new WhitehatClient(config.whitehatApiKey);

  const account = toAccountEntity(
    (await whitehat.getResources()).account,
    context.instance,
  );

  const { vulnerabilities, cveMap, serviceMap, findingMap } = processFindings(
    await getFindings(whitehat, jobs),
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
