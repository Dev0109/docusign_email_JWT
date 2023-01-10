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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/ESignPermissionProfileList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/ESignPermissionProfileList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.ESignPermissionProfilesApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.ESignPermissionProfileList);
  }
}(this, function(Configuration, ApiClient, ApiError, ESignPermissionProfileList) {
  'use strict';

  /**
   * ESignPermissionProfiles service.
   * @module api/ESignPermissionProfilesApi
   */

  /**
   * Constructs a new ESignPermissionProfilesApi. 
   * @alias module:api/ESignPermissionProfilesApi
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
     * (Optional) Callback function to receive the result of the getESignPermissionProfiles operation. If none specified a Promise will be returned.
     * @callback module:api/ESignPermissionProfilesApi~getESignPermissionProfilesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ESignPermissionProfileList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets permission profiles from the associated eSign account.
     * @param {String} accountId 
     * @param {module:api/ESignPermissionProfilesApi~getESignPermissionProfilesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ESignPermissionProfileList}
     */
    this.getESignPermissionProfiles = function(accountId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getESignPermissionProfiles");
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
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = ESignPermissionProfileList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/esign_permission_profiles', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));