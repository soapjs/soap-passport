import passport from "passport";
import { BasicStrategy } from "passport-http";
import * as Soap from "@soapjs/soap";
import { PassportBasicStrategy } from "../passport-basic.strategy";
import { AuthenticatedOnlyMiddleware } from "../../middlewares";

jest.mock("passport");
jest.mock("passport-http", () => ({
  BasicStrategy: jest.fn().mockImplementation((verify) => {
    return { name: "basic", authenticate: verify };
  }),
}));

describe("PassportBasicStrategy", () => {
  const validateMock = jest.fn();
  const basicConfig: Soap.UserPasswordConfig = {
    validate: validateMock,
    authPath: "/login",
    authHttpMethod: "post",
    failurePath: "/login",
    redirectPath: "/dashboard",
  };

  let strategy: PassportBasicStrategy;

  beforeEach(() => {
    strategy = new PassportBasicStrategy(basicConfig);
    validateMock.mockClear();
    (passport.use as jest.Mock).mockClear();
  });

  it("should initialize passport with the basic strategy", () => {
    strategy.init();
    expect(passport.use).toHaveBeenCalledWith(expect.anything());
  });

  it("should set the AuthenticatedOnlyMiddleware", () => {
    strategy.init();
    const middleware = strategy.getMiddlewares(
      Soap.MiddlewareType.AuthenticatedOnly
    );
    expect(middleware).toBeInstanceOf(AuthenticatedOnlyMiddleware);
  });

  it("should add an auth route with the correct path and method", () => {
    strategy.init();
    const route = strategy.getRoutes("auth");
    expect(route).toBeDefined();
    expect(route).toHaveProperty("path", basicConfig.authPath);
    expect(route).toHaveProperty("method", basicConfig.authHttpMethod);
  });

  it("should validate user credentials using the provided validate function", async () => {
    const done = jest.fn();
    strategy.init();
    const basicStrategy = (passport.use as jest.Mock).mock.calls[0][0]
      .authenticate;
    validateMock.mockResolvedValueOnce({ user: "testuser" });

    await basicStrategy("testuser", "testpassword", done);

    expect(validateMock).toHaveBeenCalledWith({
      username: "testuser",
      password: "testpassword",
    });
    expect(done).toHaveBeenCalledWith(null, { user: "testuser" });
  });

  it("should return error if validate function returns an error", async () => {
    const done = jest.fn();
    strategy.init();
    const basicStrategy = (passport.use as jest.Mock).mock.calls[0][0]
      .authenticate;
    const validationError = new Error("Invalid credentials");
    validateMock.mockResolvedValueOnce(validationError);

    await basicStrategy("testuser", "testpassword", done);

    expect(done).toHaveBeenCalledWith(validationError, false);
  });

  it("should call next if no redirectPath is provided", async () => {
    const req = {};
    const res = {};
    const next = jest.fn();

    strategy = new PassportBasicStrategy({
      ...basicConfig,
      redirectPath: undefined,
    });
    strategy.init();
    const route = strategy.getRoutes("auth");
    if (route && "handler" in route) {
      await route.handler(req, res, next);
    }

    expect(next).toHaveBeenCalled();
  });

  it("should redirect if redirectPath is provided", async () => {
    const req = {};
    const res = { redirect: jest.fn() };
    const next = jest.fn();

    strategy.init();
    const route = strategy.getRoutes("auth");
    if (route && "handler" in route) {
      await route.handler(req, res, next);
    }

    expect(res.redirect).toHaveBeenCalledWith(basicConfig.redirectPath);
  });
});
