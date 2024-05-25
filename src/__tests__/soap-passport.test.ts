import * as Soap from "@soapjs/soap";
import * as passport from "passport";
import { Strategy as JwtStrategy } from "passport-jwt";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as TwitterStrategy } from "passport-twitter";
import { BasicStrategy } from "passport-http";
import { Strategy as LocalStrategy } from "passport-local";
import { SoapPassport } from "../soap-passport";
import { AuthStrategy } from "../strategies";

jest.mock("passport");

class CustomStrategy extends AuthStrategy {
  initialized = false;
  init(...args: unknown[]): void {
    this.initialized = true;
  }
}

describe("SoapPassport", () => {
  let config: Soap.ApiAuthConfig;
  let soapPassport: SoapPassport;

  beforeEach(() => {
    config = {
      jwt: {
        secretOrKey: "secret",
        jwtFromRequest: jest.fn(),
        validate: jest.fn(),
      },
      apiKey: {
        apiKeyHeader: "x-api-key",
        validateApiKey: jest.fn(),
        validate: jest.fn(),
      },
      facebook: {
        clientID: "facebook-client-id",
        clientSecret: "facebook-client-secret",
        callbackURL: "localhost/auth/callback",
        authPath: "/auth",
        callbackPath: "/auth/callback",
        validate: jest.fn(),
      },
      google: {
        clientID: "google-client-id",
        clientSecret: "google-client-secret",
        callbackURL: "localhost/auth/callback",
        authPath: "/auth",
        callbackPath: "/auth/callback",
        validate: jest.fn(),
      },
      twitter: {
        clientID: "twitter-consumer-key",
        clientSecret: "twitter-consumer-secret",
        callbackURL: "localhost/auth/callback",
        authPath: "/auth",
        callbackPath: "/auth/callback",
        validate: jest.fn(),
      },
      local: {
        usernameField: "username",
        passwordField: "password",
        authPath: "/auth",
        validate: jest.fn(),
      },
      basic: { validate: jest.fn(), authPath: "/auth" },
      sessionOptions: {
        serialize: jest.fn(),
        deserialize: jest.fn(),
        validate: jest.fn(),
      },
    };
    soapPassport = new SoapPassport(config);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should initialize correctly", () => {
    expect(soapPassport).toBeInstanceOf(SoapPassport);
  });

  it("should setup JWT strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.any(JwtStrategy));
  });

  it("should setup API Key strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.anything());
  });

  it("should setup Facebook strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.any(FacebookStrategy));
  });

  it("should setup Google strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.any(GoogleStrategy));
  });

  it("should setup Twitter strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.any(TwitterStrategy));
  });

  it("should setup Local strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.any(LocalStrategy));
  });

  it("should setup Basic strategy if config is provided", () => {
    soapPassport.init();
    expect(passport.use).toHaveBeenCalledWith(expect.any(BasicStrategy));
  });

  it("should initialize passport with session options if provided", () => {
    soapPassport.init();
    expect(passport.session).toHaveBeenCalled();
    expect(passport.serializeUser).toHaveBeenCalledWith(
      config.sessionOptions.serialize
    );
    expect(passport.deserializeUser).toHaveBeenCalledWith(
      config.sessionOptions.deserialize
    );
  });

  it("should initialize passport without session if session options are not provided", () => {
    delete config.sessionOptions;
    soapPassport = new SoapPassport(config);
    soapPassport.init();
    expect(passport.session).not.toHaveBeenCalled();
    expect(passport.serializeUser).not.toHaveBeenCalled();
    expect(passport.deserializeUser).not.toHaveBeenCalled();
  });

  it("should return initialized components", () => {
    const components = soapPassport.init();
    expect(components).toContain(passport.initialize());
    if (config.sessionOptions) {
      expect(components).toContain(passport.session());
    }
  });

  it("should initialize custom strategy", () => {
    const sp = new SoapPassport({});
    sp.addStrategy("Custom", new CustomStrategy());
    sp.init();
    expect(sp.getStrategy("Custom")["initialized"]).toBe(true);
  });
});
