import * as Soap from "@soapjs/soap";
import { AuthStrategy } from "../auth-strategy";

class TestAuthStrategy extends AuthStrategy {
  init(): void {}
}

describe("AuthStrategy", () => {
  let strategy: AuthStrategy;

  beforeEach(() => {
    strategy = new TestAuthStrategy();
  });

  it("should return all middlewares if no filter is provided", () => {
    const middleware1: Soap.Middleware = {
      name: "middleware1",
      isDynamic: true,
      use: jest.fn(),
    };
    const middleware2: Soap.Middleware = {
      name: "middleware2",
      isDynamic: false,
      use: jest.fn(),
    };
    strategy["middlewares"].set("middleware1", middleware1);
    strategy["middlewares"].set("middleware2", middleware2);

    const middlewares = strategy.getMiddlewares();
    expect(middlewares).toEqual([middleware1, middleware2]);
  });

  it("should return the middleware that matches the filter string", () => {
    const middleware: Soap.Middleware = {
      name: "middleware1",
      isDynamic: true,
      use: jest.fn(),
    };
    strategy["middlewares"].set("middleware1", middleware);

    const result = strategy.getMiddlewares("middleware1");
    expect(result).toEqual(middleware);
  });

  it("should return only global middlewares if onlyGlobal filter is set", () => {
    const middleware1: Soap.Middleware = {
      name: "middleware1",
      isDynamic: true,
      use: jest.fn(),
    };
    const middleware2: Soap.Middleware = {
      name: "middleware2",
      isDynamic: false,
      use: jest.fn(),
    };
    strategy["middlewares"].set("middleware1", middleware1);
    strategy["middlewares"].set("middleware2", middleware2);

    const middlewares = strategy.getMiddlewares({ onlyGlobal: true });
    expect(middlewares).toEqual([middleware2]);
  });

  it("should return only dynamic middlewares if onlyDynamic filter is set", () => {
    const middleware1: Soap.Middleware = {
      name: "middleware1",
      isDynamic: true,
      use: jest.fn(),
    };
    const middleware2: Soap.Middleware = {
      name: "middleware2",
      isDynamic: false,
      use: jest.fn(),
    };
    strategy["middlewares"].set("middleware1", middleware1);
    strategy["middlewares"].set("middleware2", middleware2);

    const middlewares = strategy.getMiddlewares({ onlyDynamic: true });
    expect(middlewares).toEqual([middleware1]);
  });

  it("should return all routes if no filter is provided", () => {
    const route1: Soap.AuthRoute = {
      path: "/route1",
      method: "get",
      handler: jest.fn(),
    };
    const route2: Soap.AuthRoute = {
      path: "/route2",
      method: "post",
      handler: jest.fn(),
    };
    strategy["routes"].set("route1", route1);
    strategy["routes"].set("route2", route2);

    const routes = strategy.getRoutes();
    expect(routes).toEqual([route1, route2]);
  });

  it("should return the route that matches the filter string", () => {
    const route: Soap.AuthRoute = {
      path: "/route1",
      method: "get",
      handler: jest.fn(),
    };
    strategy["routes"].set("route1", route);

    const result = strategy.getRoutes("route1");
    expect(result).toEqual(route);
  });
});
