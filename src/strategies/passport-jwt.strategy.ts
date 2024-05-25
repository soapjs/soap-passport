import * as Soap from "@soapjs/soap";
import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { AuthenticatedOnlyMiddleware } from "../middlewares/authenticated-only.middleware";
import { AuthStrategy } from "./auth-strategy";

/**
 * Class representing the JWT strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportJwtStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportJwtStrategy.
   *
   * @param {Soap.JwtConfig} defaultOptions - The default configuration options for the JWT strategy.
   */
  constructor(protected defaultOptions: Soap.JwtConfig) {
    super();
  }

  /**
   * Initializes the JWT strategy for Passport.js.
   */
  init(): void {
    const { validate, ...options } = this.defaultOptions;

    if (!options.jwtFromRequest) {
      options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
    }

    passport.use(
      new JwtStrategy(options, async (payload, done) => {
        if (validate) {
          const result = await validate<unknown>(payload);
          if (result instanceof Error) {
            return done(result, false);
          }
          return done(null, result);
        }
        return done(new Error(`Missing JWT validator`), false);
      })
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("jwt")
    );
  }
}
