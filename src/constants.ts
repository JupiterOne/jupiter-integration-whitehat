import { ServiceEntityMap } from "./types";

export const WHITEHAT_ACCOUNT_ENTITY_TYPE = "whitehat_account";
export const WHITEHAT_SERVICE_ENTITY_TYPE = "whitehat_scan";
export const WHITEHAT_CVE_ENTITY_TYPE = "cve";
export const WHITEHAT_VULNERABILITY_ENTITY_TYPE = "whitehat_vulnerability";
export const WHITEHAT_FINDING_ENTITY_TYPE = "whitehat_finding";
export const WHITEHAT_ACCOUNT_SERVICE_RELATIONSHIP_TYPE =
  "whitehat_account_has_service";
export const WHITEHAT_SERVICE_VULNERABILITY_RELATIONSHIP_TYPE =
  "whitehat_scan_identified_vulnerability";
export const WHITEHAT_VULNERABILITY_CVE_RELATIONSHIP_TYPE =
  "whitehat_vulnerability_exploits_cwe";
export const WHITEHAT_VULNERABILITY_FINDING_RELATIONSHIP_TYPE =
  "whitehat_finding_is_vulnerability";
export const DEFAULT_SERVICE_ENTITY_MAP: ServiceEntityMap = {
  STATIC: {
    _class: "Service",
    _key: `whitehat-scan-static`,
    _type: WHITEHAT_SERVICE_ENTITY_TYPE,
    category: "software",
    displayName: "STATIC",
    name: "STATIC",
  },
  DYNAMIC: {
    _class: "Service",
    _key: `whitehat-scan-dynamic`,
    _type: WHITEHAT_SERVICE_ENTITY_TYPE,
    category: "software",
    displayName: "DYNAMIC",
    name: "DYNAMIC",
  },
};
