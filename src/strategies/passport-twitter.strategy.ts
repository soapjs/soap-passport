import * as Soap from "@soapjs/soap";
import passport from "passport";
import { Strategy as TwitterStrategy } from "passport-twitter";

import { AuthStrategy } from "./auth-strategy";
import { AuthenticatedOnlyMiddleware } from "../middlewares/authenticated-only.middleware";

/**
 * Class representing the Twitter strategy for Passport.js authentication.
 *
 * @extends {AuthStrategy}
 */
export class PassportTwitterStrategy extends AuthStrategy {
  protected middlewares = new Map<string, Soap.Middleware>();
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Creates an instance of PassportTwitterStrategy.
   *
   * @param {Soap.OAuthConfig} defaultOptions - The default configuration options for the Twitter strategy.
   */
  constructor(protected defaultOptions: Soap.TwitterConfig) {
    super();
  }

  /**
   * Initializes the Twitter strategy for Passport.js.
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
      new TwitterStrategy(
        {
          consumerKey: clientID,
          consumerSecret: clientSecret,
          callbackURL,
        },
        async (token, tokenSecret, profile, done) => {
          if (validate) {
            const result = await validate<unknown>(token, tokenSecret, profile);
            if (result instanceof Error) {
              return done(result, false);
            }
            return done(null, result);
          }
          return done(new Error(`Missing Twitter validator`), false);
        }
      )
    );

    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware("twitter")
    );

    this.routes.set("auth", {
      path: authPath,
      method: authHttpMethod || "get",
      middlewares: [],
      handler: passport.authenticate("twitter", options),
    });

    this.routes.set("auth_callback", {
      path: callbackPath,
      method: "get",
      middlewares: [
        passport.authenticate(
          "twitter",
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
