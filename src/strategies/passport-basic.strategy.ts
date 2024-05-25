import * as Soap from "@soapjs/soap";
import passport from "passport";
import { BasicStrategy } from "passport-http";
import { AuthStrategy } from "./auth-strategy";
import { AuthenticatedOnlyMiddleware } from "../middlewares";

/**
 * Class representing the Basic strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportBasicStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportBasicStrategy.
   *
   * @param {Soap.BasicConfig} defaultOptions - The default configuration options for the Basic strategy.
   */
  constructor(protected defaultOptions: Soap.UserPasswordConfig) {
    super();
  }

  /**
   * Initializes the Basic strategy for Passport.js.
   */
  init(): void {
    const {
      validate,
      authPath,
      authHttpMethod,
      failurePath,
      redirectPath,
      ...options
    } = this.defaultOptions;
    passport.use(
      new BasicStrategy(async (username, password, done) => {
        if (validate) {
          const result = await validate<unknown>({ username, password });
          if (result instanceof Error) {
            return done(result, false);
          }
          return done(null, result);
        }
        return done(new Error(`Missing Basic validator`), false);
      })
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("basic")
    );

    this.routes.set("auth", {
      path: authPath,
      method: authHttpMethod || "post",
      middlewares: [
        passport.authenticate("basic", options || { session: false }),
      ],
      handler: function (req, res, next) {
        if (redirectPath) {
          res.redirect(redirectPath);
        } else {
          next();
        }
      },
    });
  }
}
