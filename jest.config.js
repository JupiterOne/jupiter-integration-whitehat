const { defaults } = require("jest-config");

module.exports = {
  globalSetup: "./jest.globalSetup.js",
  transform: {
    "^.+\\.ts?$": "ts-jest",
  },
  testMatch: ["<rootDir>/src/**/*.test.{js,ts}"],
  collectCoverageFrom: [
    "src/**/*.ts",
    "!src/index.ts",
    "!src/executionHandler.ts",
    "!src/utils/getLastSyncTime.ts",
    "!src/whitehat-client.d.ts",
  ],
  moduleFileExtensions: [...defaults.moduleFileExtensions, "ts"],
  testEnvironment: "node",
  clearMocks: true,
  collectCoverage: true,
  coverageThreshold: {
    global: {
      statements: 100,
      branches: 100,
      functions: 100,
      lines: 100,
    },
  },
};
