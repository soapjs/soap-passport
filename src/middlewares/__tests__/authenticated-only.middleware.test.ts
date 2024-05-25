import * as Soap from "@soapjs/soap";
import passport from "passport";

import { AuthenticatedOnlyMiddleware } from "../authenticated-only.middleware";

// Mock Passport.js
jest.mock("passport", () => ({
  authenticate: jest.fn(() => (req, res, next) => next()),
}));

describe("AuthenticatedOnlyMiddleware", () => {
  const strategy = "jwt";
  const middleware = new AuthenticatedOnlyMiddleware(strategy);

  it("should have the correct name and isDynamic properties", () => {
    expect(middleware.name).toBe(Soap.MiddlewareType.AuthenticatedOnly);
    expect(middleware.isDynamic).toBe(true);
  });

  it("should return a middleware function from use()", () => {
    const options = { session: false };
    const middlewareFunction = middleware.use(options);
    expect(typeof middlewareFunction).toBe("function");
  });

  it("should call passport.authenticate with the correct strategy and options", () => {
    const options = { session: false };
    middleware.use(options);
    expect(passport.authenticate).toHaveBeenCalledWith(strategy, options);
  });

  it("should call passport.authenticate with the correct strategy without options", () => {
    middleware.use();
    expect(passport.authenticate).toHaveBeenCalledWith(strategy, undefined);
  });
});
