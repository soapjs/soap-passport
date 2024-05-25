import * as Soap from "@soapjs/soap";
import passport from "passport";

/**
 * Middleware for authenticating routes using a specific Passport strategy.
 *
 * @implements {Soap.Middleware}
 */
export class AuthenticatedOnlyMiddleware implements Soap.Middleware {
  /**
   * The name of the middleware.
   * @type {string}
   */
  readonly name = Soap.MiddlewareType.AuthenticatedOnly;

  /**
   * Indicates if the middleware is dynamic.
   * @type {boolean}
   */
  readonly isDynamic = true;

  /**
   * Creates an instance of AuthenticatedOnlyMiddleware.
   *
   * @param {string} strategy - The name of the Passport strategy to use.
   */
  constructor(protected strategy: string) {}

  /**
   * Returns a middleware function that authenticates requests using the specified Passport strategy.
   *
   * @param {Soap.AnyObject} [options] - Optional options for the Passport strategy.
   * @returns {Soap.AnyFunction} - The middleware function.
   */
  use(options?: Soap.AnyObject): Soap.AnyFunction {
    return passport.authenticate(this.strategy, options);
  }
}
