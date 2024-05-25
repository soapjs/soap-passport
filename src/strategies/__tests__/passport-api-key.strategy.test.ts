import passport from "passport";
import passportCustom from "passport-custom";
import * as Soap from "@soapjs/soap";
import { PassportApiKeyStrategy } from "../passport-api-key.strategy";
import { AuthenticatedOnlyMiddleware } from "../../middlewares";
jest.mock("passport");
jest.mock("passport-custom", () => ({
  Strategy: jest.fn().mockImplementation((verify) => {
    return { name: "custom", authenticate: verify };
  }),
}));

describe("PassportApiKeyStrategy", () => {
  const validateMock = jest.fn();
  const apiKeyConfig: Soap.ApiKeyConfig = {
    validate: validateMock,
    apiKeyHeader: "x-api-key",
    apiKeyQueryParam: "api_key",
  };

  let strategy: PassportApiKeyStrategy;

  beforeEach(() => {
    strategy = new PassportApiKeyStrategy(apiKeyConfig);
    validateMock.mockClear();
    (passport.use as jest.Mock).mockClear();
  });

  it("should initialize passport with the api-key strategy", () => {
    strategy.init();
    expect(passport.use).toHaveBeenCalledWith("api-key", expect.any(Object));
  });

  it("should set the AuthenticatedOnlyMiddleware", () => {
    strategy.init();
    const middleware = strategy.getMiddlewares(
      Soap.MiddlewareType.AuthenticatedOnly
    );
    expect(middleware).toBeInstanceOf(AuthenticatedOnlyMiddleware);
  });

  it("should validate api key from headers", async () => {
    const req = {
      headers: {
        "x-api-key": "test-api-key",
      },
      query: {},
    };

    const done = jest.fn();
    strategy.init();
    const apiKeyStrategy = (passport.use as jest.Mock).mock.calls[0][1];
    validateMock.mockResolvedValueOnce({ user: "test" });

    await apiKeyStrategy.authenticate(req, done);

    expect(validateMock).toHaveBeenCalledWith("test-api-key");
    expect(done).toHaveBeenCalledWith(null, { user: "test" });
  });

  it("should validate api key from custom header", async () => {
    const req = {
      headers: {
        "custom-api-key-header": "test-api-key",
      },
      query: {},
    };

    const apiKeyConfigWithCustomHeader: Soap.ApiKeyConfig = {
      ...apiKeyConfig,
      apiKeyHeader: "custom-api-key-header",
    };
    strategy = new PassportApiKeyStrategy(apiKeyConfigWithCustomHeader);
    strategy.init();
    const apiKeyStrategy = (passport.use as jest.Mock).mock.calls[0][1];
    const done = jest.fn();
    validateMock.mockResolvedValueOnce({ user: "test" });

    await apiKeyStrategy.authenticate(req, done);

    expect(validateMock).toHaveBeenCalledWith("test-api-key");
    expect(done).toHaveBeenCalledWith(null, { user: "test" });
  });

  it("should validate api key from query params", async () => {
    const req = {
      headers: {},
      query: {
        api_key: "test-api-key",
      },
    };

    const done = jest.fn();
    strategy.init();
    const apiKeyStrategy = (passport.use as jest.Mock).mock.calls[0][1];
    validateMock.mockResolvedValueOnce({ user: "test" });

    await apiKeyStrategy.authenticate(req, done);

    expect(validateMock).toHaveBeenCalledWith("test-api-key");
    expect(done).toHaveBeenCalledWith(null, { user: "test" });
  });

  it("should return error if api key is not provided", async () => {
    const req = {
      headers: {},
      query: {},
    };

    const done = jest.fn();
    strategy.init();
    const apiKeyStrategy = (passport.use as jest.Mock).mock.calls[0][1];

    await apiKeyStrategy.authenticate(req, done);

    expect(done).toHaveBeenCalledWith(new Error("API Key not provided"));
  });

  it("should return error if validate function returns an error", async () => {
    const req = {
      headers: {
        "x-api-key": "test-api-key",
      },
      query: {},
    };

    const done = jest.fn();
    strategy.init();
    const apiKeyStrategy = (passport.use as jest.Mock).mock.calls[0][1];
    const validationError = new Error("Invalid API Key");
    validateMock.mockResolvedValueOnce(validationError);

    await apiKeyStrategy.authenticate(req, done);

    expect(done).toHaveBeenCalledWith(validationError);
  });
});
