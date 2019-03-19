import {
  EntityFromIntegration,
  EntityOperation,
  IntegrationExecutionContext,
  IntegrationInvocationEvent,
  PersisterOperations,
  RelationshipFromIntegration,
  RelationshipOperation,
} from "@jupiterone/jupiter-managed-integration-sdk";
import {
  WHITEHAT_ACCOUNT_ENTITY_TYPE,
  WHITEHAT_ACCOUNT_SERVICE_RELATIONSHIP_TYPE,
  WHITEHAT_FINDING_ENTITY_TYPE,
  WHITEHAT_SERVICE_ENTITY_TYPE,
  WHITEHAT_SERVICE_VULNERABILITY_RELATIONSHIP_TYPE,
  WHITEHAT_VULNERABILITY_CVE_RELATIONSHIP_TYPE,
  WHITEHAT_VULNERABILITY_ENTITY_TYPE,
  WHITEHAT_VULNERABILITY_FINDING_RELATIONSHIP_TYPE,
} from "./constants";
import {
  toAccountServiceRelationship,
  toServiceVulnerabilityRelationship,
  toVulnerabilityCVERelationship,
  toVulnerabilityFindingRelationship,
} from "./converters";
import {
  AccountEntity,
  AccountServiceRelationship,
  CVEEntityMap,
  FindingEntity,
  FindingEntityMap,
  ServiceEntityMap,
  ServiceVulnerabilityRelationship,
  VulnerabilityCVERelationship,
  VulnerabilityEntity,
  VulnerabilityFindingRelationship,
} from "./types";

export async function createOperationsFromFindings(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
  accountEntity: AccountEntity,
  vulnerabilityEntities: VulnerabilityEntity[],
  cveMap: CVEEntityMap,
  serviceMap: ServiceEntityMap,
  findingMap: FindingEntityMap,
): Promise<PersisterOperations> {
  const accountServiceRelationships: AccountServiceRelationship[] = [];
  const serviceVulnerabilityRelationships: ServiceVulnerabilityRelationship[] = [];
  const vulnerabilityCVERelationships: VulnerabilityCVERelationship[] = [];
  const vulnerabilityFindingRelationships: VulnerabilityFindingRelationship[] = [];

  const findingEntities: FindingEntity[] = [];

  for (const serviceEntity of Object.values(serviceMap)) {
    accountServiceRelationships.push(
      toAccountServiceRelationship(accountEntity, serviceEntity),
    );
  }

  for (const vulnerability of vulnerabilityEntities) {
    const service = serviceMap[vulnerability.scanType];
    serviceVulnerabilityRelationships.push(
      toServiceVulnerabilityRelationship(service, vulnerability),
    );

    const cves = cveMap[vulnerability.id];
    for (const cve of cves) {
      vulnerabilityCVERelationships.push(
        toVulnerabilityCVERelationship(vulnerability, cve),
      );
    }

    const findings = findingMap[vulnerability.id];
    for (const finding of findings) {
      findingEntities.push(finding);
      vulnerabilityFindingRelationships.push(
        toVulnerabilityFindingRelationship(vulnerability, finding),
      );
    }
  }

  const entityOperations = [
    ...(await toEntityOperations(
      context,
      vulnerabilityEntities,
      WHITEHAT_VULNERABILITY_ENTITY_TYPE,
    )),
    ...(await toEntityOperations(
      context,
      Object.values(serviceMap),
      WHITEHAT_SERVICE_ENTITY_TYPE,
    )),
    ...(await toEntityOperations(
      context,
      findingEntities,
      WHITEHAT_FINDING_ENTITY_TYPE,
    )),
  ];

  const relationshipOperations = [
    ...(await toRelationshipOperations(
      context,
      accountServiceRelationships,
      WHITEHAT_ACCOUNT_SERVICE_RELATIONSHIP_TYPE,
    )),
    ...(await toRelationshipOperations(
      context,
      serviceVulnerabilityRelationships,
      WHITEHAT_SERVICE_VULNERABILITY_RELATIONSHIP_TYPE,
    )),
    ...(await toRelationshipOperations(
      context,
      vulnerabilityCVERelationships,
      WHITEHAT_VULNERABILITY_CVE_RELATIONSHIP_TYPE,
    )),
    ...(await toRelationshipOperations(
      context,
      vulnerabilityFindingRelationships,
      WHITEHAT_VULNERABILITY_FINDING_RELATIONSHIP_TYPE,
    )),
  ];

  return [entityOperations, relationshipOperations];
}

export async function createOperationsFromAccount(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
  accountEntity: AccountEntity,
): Promise<PersisterOperations> {
  return [
    await toEntityOperations(
      context,
      [accountEntity],
      WHITEHAT_ACCOUNT_ENTITY_TYPE,
    ),
    [],
  ];
}

async function toEntityOperations<T extends EntityFromIntegration>(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
  entities: T[],
  type: string,
): Promise<EntityOperation[]> {
  const { graph, persister } = context.clients.getClients();

  const oldEntities = await graph.findEntities({
    _accountId: context.instance.accountId,
    _deleted: false,
    _integrationInstanceId: context.instance.id,
    _type: type,
  });

  return persister.processEntities(oldEntities, entities);
}

async function toRelationshipOperations<T extends RelationshipFromIntegration>(
  context: IntegrationExecutionContext<IntegrationInvocationEvent>,
  relationships: T[],
  type: string,
): Promise<RelationshipOperation[]> {
  const { graph, persister } = context.clients.getClients();

  const oldRelationships = await graph.findRelationships({
    _accountId: context.instance.accountId,
    _deleted: false,
    _integrationInstanceId: context.instance.id,
    _type: type,
  });

  return persister.processRelationships(oldRelationships, relationships);
}
