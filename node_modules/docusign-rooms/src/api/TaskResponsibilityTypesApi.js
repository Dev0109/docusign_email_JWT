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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/GlobalTaskResponsibilityTypes'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/GlobalTaskResponsibilityTypes'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.TaskResponsibilityTypesApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.GlobalTaskResponsibilityTypes);
  }
}(this, function(Configuration, ApiClient, ApiError, GlobalTaskResponsibilityTypes) {
  'use strict';

  /**
   * TaskResponsibilityTypes service.
   * @module api/TaskResponsibilityTypesApi
   */

  /**
   * Constructs a new TaskResponsibilityTypesApi. 
   * @alias module:api/TaskResponsibilityTypesApi
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
     * (Optional) Callback function to receive the result of the getTaskResponsibilityTypes operation. If none specified a Promise will be returned.
     * @callback module:api/TaskResponsibilityTypesApi~getTaskResponsibilityTypesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/GlobalTaskResponsibilityTypes} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Retrieves the list of valid task responsibility types.
     * @param {module:api/TaskResponsibilityTypesApi~getTaskResponsibilityTypesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/GlobalTaskResponsibilityTypes}
     */
    this.getTaskResponsibilityTypes = function(callback) {
      var postBody = null;

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
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
      var returnType = GlobalTaskResponsibilityTypes;

      return this.apiClient.callApi(
        '/v2/task_responsibility_types', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));