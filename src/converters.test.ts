import WhitehatClient from "@jupiterone/whitehat-client";
import mockWhitehatClient from "../test/helpers/mockWhitehatClient";
import { FindingData, toFindingEntity } from "./converters";

jest.mock("@jupiterone/whitehat-client", () => {
  return jest.fn().mockImplementation(() => mockWhitehatClient);
});

test("convert to finding entity", async () => {
  const mockedClient = new WhitehatClient("TestConfig");
  const findings: FindingData[] = await mockedClient.getVulnerabilities({
    queryParams: "test",
  });
  expect(toFindingEntity(findings[0])).toEqual({
    _class: "Finding",
    _key: "whitehat-finding-987",
    _type: "whitehat_finding",
    createdOn: 1555969433000,
    cvss: "6.9",
    displayName: "My Mock Class",
    foundDate: 1555969433000,
    impact: 5,
    likelihood: 2,
    location: "somewhere.js",
    modifiedDate: 1555969433000,
    name: "My.Mock.Class",
    open: true,
    resolvedDate: null,
    risk: "low",
    targets: "my-app",
  });
});
