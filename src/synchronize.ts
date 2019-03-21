import {
  IntegrationExecutionContext,
  IntegrationInvocationEvent,
  PersisterOperationsResult,
} from "@jupiterone/jupiter-managed-integration-sdk";
import WhitehatClient from "@jupiterone/whitehat-client";
import {
  FindingData,
  toAccountEntity,
  toCVEEntities,
  toFindingEntity,
  toServiceEntity,
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
  VulnerabilityEntityMap,
  WhitehatIntegrationInstanceConfig,
} from "./types";

export default async function synchronize(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
): Promise<PersisterOperationsResult> {
  const config = context.instance.config as WhitehatIntegrationInstanceConfig;

  const whitehat = new WhitehatClient(config.whitehatApiKey);

  const account = toAccountEntity(
    (await whitehat.getResources()).account,
    context.instance,
  );

  const vulnerabilityMap: VulnerabilityEntityMap = {};
  const cveMap: CVEEntityMap = {};
  const serviceMap: ServiceEntityMap = {};
  const findingMap: FindingEntityMap = {};

  const findings: FindingData[] = await whitehat.getVulnerabilities({
    queryParams: ["query_status=open,closed"],
  });

  for (const finding of findings) {
    vulnerabilityMap[finding.class] = toVulnerabilityEntity(finding);

    cveMap[finding.class] = toCVEEntities(finding);
    // TODO: fetch dynamic scans from dynamic scan api
    serviceMap.STATIC = toServiceEntity();

    findingMap[finding.class] = findingMap[finding.class] || [];
    findingMap[finding.class].push(toFindingEntity(finding));
  }

  const { persister } = context.clients.getClients();
  return persister.publishPersisterOperations(
    await createOperationsFromAccount(context, account),
    await createOperationsFromFindings(
      context,
      account,
      Object.values(vulnerabilityMap),
      cveMap,
      serviceMap,
      findingMap,
    ),
  );
}
