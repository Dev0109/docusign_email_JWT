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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/FormLibrarySummaryList', 'model/FormSummaryList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/FormLibrarySummaryList'), require('../model/FormSummaryList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.FormLibrariesApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.FormLibrarySummaryList, root.DocusignRooms.FormSummaryList);
  }
}(this, function(Configuration, ApiClient, ApiError, FormLibrarySummaryList, FormSummaryList) {
  'use strict';

  /**
   * FormLibraries service.
   * @module api/FormLibrariesApi
   */

  /**
   * Constructs a new FormLibrariesApi. 
   * @alias module:api/FormLibrariesApi
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
     * (Optional) Callback function to receive the result of the getFormLibraries operation. If none specified a Promise will be returned.
     * @callback module:api/FormLibrariesApi~getFormLibrariesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormLibrarySummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets a paged list of forms libraries.
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.count Default value is 100 and max value is 100 (default to 100)
     * @param {Number} optsOrCallback.startPosition Default value is 0 (default to 0)
     * @param {module:api/FormLibrariesApi~getFormLibrariesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormLibrarySummaryList}
     */
    this.getFormLibraries = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getFormLibraries");
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
        'count': optsOrCallback['count'],
        'startPosition': optsOrCallback['startPosition']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = FormLibrarySummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_libraries', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getFormLibraryForms operation. If none specified a Promise will be returned.
     * @callback module:api/FormLibrariesApi~getFormLibraryFormsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormSummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets a paged list of forms in a forms library.
     * @param {String} accountId 
     * @param {String} formLibraryId Library Id
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.count Default value is 100 and max value is 100 (default to 100)
     * @param {Number} optsOrCallback.startPosition Default value is 0 (default to 0)
     * @param {module:api/FormLibrariesApi~getFormLibraryFormsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormSummaryList}
     */
    this.getFormLibraryForms = function(accountId, formLibraryId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getFormLibraryForms");
      }

      // verify the required parameter 'formLibraryId' is set
      if (formLibraryId === undefined || formLibraryId === null) {
        throw new Error("Missing the required parameter 'formLibraryId' when calling getFormLibraryForms");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formLibraryId': formLibraryId
      };
      var queryParams = {
        'count': optsOrCallback['count'],
        'startPosition': optsOrCallback['startPosition']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = FormSummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_libraries/{formLibraryId}/forms', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));