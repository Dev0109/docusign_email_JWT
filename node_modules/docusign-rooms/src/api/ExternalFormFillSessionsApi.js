/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/ExternalFormFillSession', 'model/ExternalFormFillSessionForCreate'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/ExternalFormFillSession'), require('../model/ExternalFormFillSessionForCreate'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.ExternalFormFillSessionsApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.ExternalFormFillSession, root.DocusignRooms.ExternalFormFillSessionForCreate);
  }
}(this, function(Configuration, ApiClient, ApiError, ExternalFormFillSession, ExternalFormFillSessionForCreate) {
  'use strict';

  /**
   * ExternalFormFillSessions service.
   * @module api/ExternalFormFillSessionsApi
   */

  /**
   * Constructs a new ExternalFormFillSessionsApi. 
   * @alias module:api/ExternalFormFillSessionsApi
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
     * (Optional) Callback function to receive the result of the createExternalFormFillSession operation. If none specified a Promise will be returned.
     * @callback module:api/ExternalFormFillSessionsApi~createExternalFormFillSessionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ExternalFormFillSession} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates an external form fill session.
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/ExternalFormFillSessionForCreate} optsOrCallback.body 
     * @param {module:api/ExternalFormFillSessionsApi~createExternalFormFillSessionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ExternalFormFillSession}
     */
    this.createExternalFormFillSession = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createExternalFormFillSession");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = ['application/json-patch+json', 'application/json', 'text/json', 'application/_*+json'];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = ExternalFormFillSession;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/external_form_fill_sessions', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));