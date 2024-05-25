import * as Soap from "@soapjs/soap";

/**
 * Abstract class representing an authentication strategy.
 *
 * @implements {Soap.ApiAuthStrategy}
 */
export abstract class AuthStrategy implements Soap.ApiAuthStrategy {
  /**
   * A map of middleware used by the authentication strategy.
   * @type {Map<string, Soap.Middleware>}
   */
  protected middlewares = new Map<string, Soap.Middleware>();

  /**
   * A map of routes used by the authentication strategy.
   * @type {Map<string, Soap.AuthRoute>}
   */
  protected routes = new Map<string, Soap.AuthRoute>();

  /**
   * Initializes the authentication strategy.
   * This method should be implemented by subclasses.
   */
  abstract init(): void;

  /**
   * Retrieves middleware(s) based on the provided filter.
   *
   * @param {string | { onlyGlobal?: boolean; onlyDynamic?: boolean }} [filter] - The filter to apply.
   * @returns {Soap.Middleware | Soap.Middleware[] | undefined} The middleware(s) that match the filter.
   */
  getMiddlewares(
    filter?: string | { onlyGlobal?: boolean; onlyDynamic?: boolean }
  ): Soap.Middleware | Soap.Middleware[] | undefined {
    if (!filter) {
      return Array.from(this.middlewares.values());
    }

    if (typeof filter === "string") {
      return this.middlewares.get(filter);
    }

    if (filter?.onlyGlobal) {
      return Array.from(this.middlewares.values()).filter(
        (middleware) => middleware.isDynamic === false
      );
    }

    if (filter?.onlyDynamic) {
      return Array.from(this.middlewares.values()).filter(
        (middleware) => middleware.isDynamic
      );
    }
  }

  /**
   * Retrieves route(s) based on the provided filter.
   *
   * @param {string} [filter] - The filter to apply.
   * @returns {Soap.AuthRoute | Soap.AuthRoute[] | undefined} The route(s) that match the filter.
   */
  getRoutes?(filter?: string): Soap.AuthRoute | Soap.AuthRoute[] | undefined {
    if (!filter) {
      return Array.from(this.routes.values());
    }

    if (typeof filter === "string") {
      return this.routes.get(filter);
    }
  }
}
