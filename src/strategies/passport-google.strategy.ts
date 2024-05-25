import * as Soap from "@soapjs/soap";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

import { AuthStrategy } from "./auth-strategy";
import { AuthenticatedOnlyMiddleware } from "../middlewares/authenticated-only.middleware";

/**
 * Class representing the Google strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportGoogleStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportGoogleStrategy.
   *
   * @param {Soap.OAuthConfig} defaultOptions - The default configuration options for the Google strategy.
   */
  constructor(protected defaultOptions: Soap.GoogleConfig) {
    super();
  }

  /**
   * Initializes the Google strategy for Passport.js.
   */
  init(): void {
    const {
      validate,
      authPath,
      callbackPath,
      failurePath,
      redirectPath,
      scope,
      authHttpMethod,
      clientID,
      clientSecret,
      callbackURL,
      ...options
    } = this.defaultOptions;

    passport.use(
      new GoogleStrategy(
        {
          clientID,
          clientSecret,
          callbackURL,
        },
        async (accessToken, refreshToken, profile, done) => {
          if (validate) {
            const result = await validate<unknown>(
              accessToken,
              refreshToken,
              profile
            );
            if (result instanceof Error) {
              return done(result, false);
            }
            return done(null, result);
          }
          return done(new Error(`Missing Google validator`), false);
        }
      )
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("google")
    );

    this.routes.set("auth", {
      path: authPath,
      method: authHttpMethod || "get",
      middlewares: [],
      handler: passport.authenticate("google", options),
    });

    this.routes.set("auth_callback", {
      path: callbackPath,
      method: "get",
      middlewares: [
        passport.authenticate(
          "google",
          failurePath
            ? {
                failureRedirect: failurePath,
                failureMessage: true,
              }
            : {}
        ),
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
