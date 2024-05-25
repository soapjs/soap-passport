import * as Soap from "@soapjs/soap";
import passport from "passport";
import { Strategy as FacebookStrategy } from "passport-facebook";

import { AuthStrategy } from "./auth-strategy";
import { AuthenticatedOnlyMiddleware } from "../middlewares/authenticated-only.middleware";

/**
 * Class representing the Facebook strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportFacebookStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportFacebookStrategy.
   *
   * @param {Soap.OAuthConfig} defaultOptions - The default configuration options for the Facebook strategy.
   */
  constructor(protected defaultOptions: Soap.FacebookConfig) {
    super();
  }

  /**
   * Initializes the Facebook strategy for Passport.js.
   */
  init(): void {
    const {
      validate,
      authPath,
      callbackPath,
      failurePath,
      redirectPath,
      authHttpMethod,
      clientID,
      clientSecret,
      callbackURL,
      ...options
    } = this.defaultOptions;

    passport.use(
      new FacebookStrategy(
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
          return done(new Error(`Missing Facebook validator`), false);
        }
      )
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("facebook")
    );

    this.routes.set("auth", {
      path: authPath,
      method: authHttpMethod || "get",
      middlewares: [],
      handler: passport.authenticate("facebook", options),
    });

    this.routes.set("auth_callback", {
      path: callbackPath,
      method: "get",
      middlewares: [
        passport.authenticate(
          "facebook",
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
