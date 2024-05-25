import * as Soap from "@soapjs/soap";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";

import { AuthenticatedOnlyMiddleware } from "../middlewares";
import { AuthStrategy } from "./auth-strategy";

/**
 * Class representing the Local strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportLocalStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportLocalStrategy.
   *
   * @param {Soap.LocalConfig} defaultOptions - The default configuration options for the Local strategy.
   */
  constructor(protected defaultOptions: Soap.UserPasswordConfig) {
    super();
  }

  /**
   * Initializes the Local strategy for Passport.js.
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
      new LocalStrategy(async (username, password, done) => {
        if (validate) {
          const result = await validate<unknown>({ username, password });
          if (result instanceof Error) {
            return done(result, false);
          }
          return done(null, result);
        }
        return done(new Error(`Missing Local validator`), false);
      })
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("local")
    );

    this.routes.set("auth", {
      path: authPath,
      method: authHttpMethod || "post",
      middlewares: [passport.authenticate("local", options)],
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
