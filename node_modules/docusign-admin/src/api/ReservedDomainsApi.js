/**
 * DocuSign Admin API
 * An API for an organization administrator to manage organizations, accounts and users
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
	define(['Configuration', 'ApiClient', 'model/DomainsResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/DomainsResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.ReservedDomainsApi = factory(root.DocusignAdmin.Configuration, root.DocusignAdmin.ApiClient, root.DocusignAdmin.DomainsResponse);
  }
}(this, function(Configuration, ApiClient, DomainsResponse) {
  'use strict';

  /**
   * ReservedDomains service.
   * @module api/ReservedDomainsApi
   */

  /**
   * Constructs a new ReservedDomainsApi. 
   * @alias module:api/ReservedDomainsApi
   * @class
   * @param {module:ApiClient} apiClient Optional API client implementation to use,
   * default to {@link module:ApiClient#instance} if unspecified.
   */
  var exports = function(apiClient) {
    this.apiClient = apiClient || Configuration.default.getDefaultApiClient() || ApiClient.instance;


    this.setApiClient = function(apiClient) {
      this.apiClient = apiClient;
    };

    this.getApiClient = function() {
      return this.apiClient;
    };


    /**
     * (Optional) Callback function to receive the result of the getReservedDomains operation. If none specified a Promise will be returned.
     * @callback module:api/ReservedDomainsApi~getReservedDomainsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DomainsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the list of reserved domains for the organization.
     * Required scopes: domain_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/ReservedDomainsApi~getReservedDomainsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DomainsResponse}
     */
    this.getReservedDomains = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getReservedDomains");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = DomainsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/reserved_domains', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));