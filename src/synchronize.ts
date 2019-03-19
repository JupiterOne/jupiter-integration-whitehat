import {
  IntegrationExecutionContext,
  IntegrationInvocationEvent,
  PersisterOperationsResult,
} from "@jupiterone/jupiter-managed-integration-sdk";
import WhitehatClient from "@jupiterone/whitehat-client";
import pMap from "p-map";
import {
  ApplicationData,
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

  const applications = await whitehat.getApplications();
  const account = toAccountEntity(
    (await whitehat.getResources()).account,
    context.instance,
  );

  const vulnerabilityMap: VulnerabilityEntityMap = {};
  const cveMap: CVEEntityMap = {};
  const serviceMap: ServiceEntityMap = {};
  const findingMap: FindingEntityMap = {};

  await pMap(
    applications,
    async (application: ApplicationData) => {
      const findings = await whitehat.getVulnerabilities(application.id);

      for (const finding of findings) {
        vulnerabilityMap[finding.class] = toVulnerabilityEntity(finding);

        cveMap[finding.class] = toCVEEntities(finding);
        // TODO: fetch dynamic scans from dynamic scan api
        serviceMap.STATIC = toServiceEntity();

        findingMap[finding.class] = findingMap[finding.class] || [];
        findingMap[finding.class].push(toFindingEntity(finding, application));
      }
    },
    { concurrency: 3 },
  );

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
