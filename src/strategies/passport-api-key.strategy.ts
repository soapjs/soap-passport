import * as Soap from "@soapjs/soap";
import passport from "passport";
import passportCustom from "passport-custom";
import { AuthStrategy } from "./auth-strategy";
import { AuthenticatedOnlyMiddleware } from "../middlewares";

/**
 * Class representing the API-Key strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportApiKeyStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportApiKeyStrategy.
   *
   * @param {Soap.ApiKeyConfig} defaultOptions - The default configuration options for the API-Key strategy.
   */
  constructor(protected defaultOptions: Soap.ApiKeyConfig) {
    super();
  }

  /**
   * Initializes the API-Key strategy for Passport.js.
   */
  init(): void {
    const { validate, apiKeyHeader, apiKeyQueryParam } = this.defaultOptions;
    passport.use(
      "api-key",
      new passportCustom.Strategy(async (req, done) => {
        let apiKey: string;
        if (apiKeyHeader && req.headers[apiKeyHeader]) {
          apiKey = req.headers[apiKeyHeader] as string;
        } else if (req.headers["x-api-key"]) {
          apiKey = req.headers["x-api-key"] as string;
        } else if (apiKeyQueryParam && req.query[apiKeyQueryParam]) {
          apiKey = req.query[apiKeyQueryParam] as string;
        }

        if (!apiKey) {
          return done(new Error("API Key not provided"));
        }

        const result = await validate<unknown | Error>(apiKey);

        if (result instanceof Error) {
          return done(result);
        }

        return done(null, result);
      })
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("api-key")
    );
  }
}
