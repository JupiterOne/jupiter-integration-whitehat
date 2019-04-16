import {
  IntegrationInstance,
  RelationshipDirection,
} from "@jupiterone/jupiter-managed-integration-sdk";
import {
  WHITEHAT_ACCOUNT_ENTITY_TYPE,
  WHITEHAT_ACCOUNT_SERVICE_RELATIONSHIP_TYPE,
  WHITEHAT_CVE_ENTITY_TYPE,
  WHITEHAT_FINDING_ENTITY_TYPE,
  WHITEHAT_SERVICE_VULNERABILITY_RELATIONSHIP_TYPE,
  WHITEHAT_VULNERABILITY_CVE_RELATIONSHIP_TYPE,
  WHITEHAT_VULNERABILITY_ENTITY_TYPE,
  WHITEHAT_VULNERABILITY_FINDING_RELATIONSHIP_TYPE,
} from "./constants";
import {
  AccountEntity,
  AccountServiceRelationship,
  CVEEntity,
  FindingEntity,
  ServiceEntity,
  ServiceVulnerabilityRelationship,
  VulnerabilityCVERelationship,
  VulnerabilityEntity,
  VulnerabilityFindingRelationship,
} from "./types";

export interface AccountData {
  company: string;
}

export interface ApplicationData {
  id: string;
  label: string;
}

interface CVEData {
  link: string;
  title: string;
}

interface CVEReference {
  collection: CVEData[];
}

export interface FindingData {
  id: number;

  application: ApplicationData;

  status: string;

  cve_reference: CVEReference;
  cvss_v3_score: string;
  cvss_v3_vector: string;

  likelihood: number;
  impact: number;
  risk: string;

  class: string;
  class_readable: string;

  location: string;

  found: string;
  opened: string;
  modified: string;
  closed: string | null;
}

export function toAccountEntity(
  account: AccountData,
  instance: IntegrationInstance,
): AccountEntity {
  return {
    _class: "Account",
    _key: instance.id,
    _type: WHITEHAT_ACCOUNT_ENTITY_TYPE,
    name: account.company,
    displayName: account.company,
  };
}

export function toCVEEntities(finding: FindingData): CVEEntity[] {
  const cveEntities: CVEEntity[] = [];

  for (const cve of finding.cve_reference.collection) {
    cveEntities.push({
      _class: "Vulnerability",
      _key: cve.title,
      _type: WHITEHAT_CVE_ENTITY_TYPE,
      name: cve.title,
      displayName: cve.title,
      references: [cve.link],
      webLink: cve.link,
    });
  }

  return cveEntities;
}

export function toVulnerabilityEntity(
  finding: FindingData,
): VulnerabilityEntity {
  return {
    _class: "Vulnerability",
    _key: `whitehat-vulnerability-${finding.class
      .toLowerCase()
      .split(".")
      .join("-")}`,
    _type: WHITEHAT_VULNERABILITY_ENTITY_TYPE,
    category: "application",
    id: finding.class,
    name: finding.class_readable,
    displayName: finding.class_readable,
    scanType: "STATIC",
  };
}

export function toFindingEntity(finding: FindingData): FindingEntity {
  return {
    _class: "Finding",
    _key: `whitehat-finding-${finding.id}`,
    _type: WHITEHAT_FINDING_ENTITY_TYPE,

    name: finding.class,
    displayName: finding.class_readable,

    impacts: finding.application.label.split("/").pop() as string,

    open: finding.status === "open",

    cvss: finding.cvss_v3_score,
    likelihood: finding.likelihood,
    impact: finding.impact,
    risk: finding.risk,

    foundDate: finding.found,
    modifiedDate: finding.modified,
    resolvedDate: finding.closed,

    location: finding.location,
  };
}

export function toAccountServiceRelationship(
  accountEntity: AccountEntity,
  serviceEntity: ServiceEntity,
): AccountServiceRelationship {
  return {
    _class: "HAS",
    _key: `${accountEntity._key}|has|${serviceEntity._key}`,
    _type: WHITEHAT_ACCOUNT_SERVICE_RELATIONSHIP_TYPE,

    _fromEntityKey: accountEntity._key,
    _toEntityKey: serviceEntity._key,
  };
}

export function toServiceVulnerabilityRelationship(
  serviceEntity: ServiceEntity,
  vulnerabilityEntity: VulnerabilityEntity,
): ServiceVulnerabilityRelationship {
  return {
    _class: "IDENTIFIED",
    _key: `${serviceEntity._key}|identified|${vulnerabilityEntity._key}`,
    _type: WHITEHAT_SERVICE_VULNERABILITY_RELATIONSHIP_TYPE,

    _fromEntityKey: serviceEntity._key,
    _toEntityKey: vulnerabilityEntity._key,
  };
}

export function toVulnerabilityCVERelationship(
  vulnerabilityEntity: VulnerabilityEntity,
  cveEntity: CVEEntity,
): VulnerabilityCVERelationship {
  return {
    _class: "EXPLOITS",
    _key: `${vulnerabilityEntity._key}|exploits|${cveEntity._key}`,
    _type: WHITEHAT_VULNERABILITY_CVE_RELATIONSHIP_TYPE,

    _fromEntityKey: vulnerabilityEntity._key,
    _toEntityKey: cveEntity._key as string,

    _mapping: {
      relationshipDirection: RelationshipDirection.FORWARD,
      sourceEntityKey: vulnerabilityEntity._key,
      targetEntity: cveEntity,
      targetFilterKeys: ["_key"],
    },

    displayName: "EXPLOITS",
  };
}

export function toVulnerabilityFindingRelationship(
  vulnerabilityEntity: VulnerabilityEntity,
  findingEntity: FindingEntity,
): VulnerabilityFindingRelationship {
  return {
    _class: "IS",
    _key: `${findingEntity._key}|is|${vulnerabilityEntity._key}`,
    _type: WHITEHAT_VULNERABILITY_FINDING_RELATIONSHIP_TYPE,

    _fromEntityKey: findingEntity._key,
    _toEntityKey: vulnerabilityEntity._key,
  };
}
