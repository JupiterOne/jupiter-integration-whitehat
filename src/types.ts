import {
  EntityFromIntegration,
  RelationshipFromIntegration,
  RelationshipMapping,
  TargetEntityProperties,
} from "@jupiterone/jupiter-managed-integration-sdk";

export interface WhitehatIntegrationInstanceConfig {
  whitehatApiKey: string;
}

export interface AccountEntity extends EntityFromIntegration {
  name: string;
}

export interface ServiceEntityMap {
  [scanType: string]: ServiceEntity;
}

export interface ServiceEntity extends EntityFromIntegration {
  category: string;
  name: string;
}

export interface VulnerabilityEntityMap {
  [id: string]: VulnerabilityEntity;
}

export interface VulnerabilityEntity extends EntityFromIntegration {
  id: string;
  category: string;
  name: string;
  scanType: string;
  createdOn: number;
}

export interface FindingEntityMap {
  [vulnerabilityClass: string]: FindingEntity[];
}

export interface FindingEntity extends EntityFromIntegration {
  name: string;

  targets: string;

  open: boolean;

  cvss: string;
  likelihood: number;
  impact: number;
  risk: string;

  createdOn: number;
  foundDate: number;
  modifiedDate: number;
  resolvedDate: number | null;

  location: string;
}

export interface CVEEntityMap {
  [id: string]: CVEEntity[];
}

export interface CVEEntity extends TargetEntityProperties {
  name: string;
  references: string[];
}

export type AccountServiceRelationship = RelationshipFromIntegration;

export type ServiceVulnerabilityRelationship = RelationshipFromIntegration;

export type VulnerabilityFindingRelationship = RelationshipFromIntegration;

export interface VulnerabilityCVERelationship
  extends RelationshipFromIntegration {
  _mapping: RelationshipMapping;
}
