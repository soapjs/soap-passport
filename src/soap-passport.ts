import * as Soap from "@soapjs/soap";
import passport, { InitializeOptions } from "passport";
import { StrategyType } from "./strategies/enums";
import {
  PassportApiKeyStrategy,
  PassportBasicStrategy,
  PassportFacebookStrategy,
  PassportGoogleStrategy,
  PassportJwtStrategy,
  PassportLocalStrategy,
  PassportTwitterStrategy,
} from "./strategies";

/**
 * Class representing the Passport.js integration for the SoapJS authentication module.
 *
 * @extends {Soap.ApiAuthModule}
 */
export class SoapPassport extends Soap.ApiAuthModule {
  /**
   * Creates an instance of SoapPassport.
   *
   * @param {Soap.ApiAuthConfig} config - The configuration options for the authentication strategies.
   */
  constructor(private config: Soap.ApiAuthConfig) {
    super();
    if (this.config.jwt) {
      const strategy = new PassportJwtStrategy(this.config.jwt);
      this.addStrategy(StrategyType.JWT, strategy);
    }
    if (this.config.apiKey) {
      const strategy = new PassportApiKeyStrategy(this.config.apiKey);
      this.addStrategy(StrategyType.ApiKey, strategy);
    }
    if (this.config.facebook) {
      const strategy = new PassportFacebookStrategy(this.config.facebook);
      this.addStrategy(StrategyType.Facebook, strategy);
    }
    if (this.config.google) {
      const strategy = new PassportGoogleStrategy(this.config.google);
      this.addStrategy(StrategyType.Google, strategy);
    }
    if (this.config.twitter) {
      const strategy = new PassportTwitterStrategy(this.config.twitter);
      this.addStrategy(StrategyType.Twitter, strategy);
    }
    if (this.config.local) {
      const strategy = new PassportLocalStrategy(this.config.local);
      this.addStrategy(StrategyType.Local, strategy);
    }
    if (this.config.basic) {
      const strategy = new PassportBasicStrategy(this.config.basic);
      this.addStrategy(StrategyType.Basic, strategy);
    }
  }

  /**
   * Initializes Passport.js with the provided options and sets up the authentication strategies.
   *
   * @param {InitializeOptions} [options] - Optional initialization options for Passport.js.
   * @returns {InitializedType[]} An array of initialized middleware components.
   */
  init<InitializedType = any>(options?: InitializeOptions): InitializedType[] {
    const components: InitializedType[] = [];
    if (this.config.sessionOptions) {
      components.push(passport.session());

      if (this.config.sessionOptions.serialize) {
        passport.serializeUser(this.config.sessionOptions.serialize);
      }

      if (this.config.sessionOptions.deserialize) {
        passport.deserializeUser(this.config.sessionOptions.deserialize);
      }
    }

    components.push(passport.initialize(options) as InitializedType);

    this.strategies.forEach((strategy) => {
      strategy.init();
    });

    return components;
  }
}
