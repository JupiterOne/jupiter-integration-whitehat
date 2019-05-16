import {
  AccountData,
  ApplicationData,
  FindingData,
} from "../../src/converters";

interface ResourcesData {
  account: AccountData;
}

const mockApplication: ApplicationData = {
  id: "123456",
  label: "my-app",
};

const mockFinding: FindingData = {
  application: mockApplication,
  class: "My.Mock.Class",
  class_readable: "My Mock Class",
  closed: null,
  cve_reference: {
    collection: [
      {
        link: "https://cve-website.com/cve",
        title: "Very Bad Vulnerability",
      },
    ],
  },
  cvss_v3_score: "6.9",
  cvss_v3_vector: "A:B:C:D:E:F:G",
  found: "2019-04-22T21:43:53.000Z",
  id: 987,
  impact: 5,
  likelihood: 2,
  location: "somewhere.js",
  modified: "2019-04-22T21:43:53.000Z",
  opened: "2019-04-22T21:43:53.000Z",
  risk: "low",
  status: "open",
};

const mockResources: ResourcesData = {
  account: {
    company: "LifeOmic",
  },
};

export default {
  getVulnerabilities: jest.fn().mockResolvedValue([mockFinding]),
  getResources: jest.fn().mockResolvedValue(mockResources),
};
