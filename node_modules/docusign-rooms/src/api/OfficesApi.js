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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/Office', 'model/OfficeForCreate', 'model/OfficeReferenceCountList', 'model/OfficeSummaryList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/Office'), require('../model/OfficeForCreate'), require('../model/OfficeReferenceCountList'), require('../model/OfficeSummaryList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.OfficesApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.Office, root.DocusignRooms.OfficeForCreate, root.DocusignRooms.OfficeReferenceCountList, root.DocusignRooms.OfficeSummaryList);
  }
}(this, function(Configuration, ApiClient, ApiError, Office, OfficeForCreate, OfficeReferenceCountList, OfficeSummaryList) {
  'use strict';

  /**
   * Offices service.
   * @module api/OfficesApi
   */

  /**
   * Constructs a new OfficesApi. 
   * @alias module:api/OfficesApi
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
     * (Optional) Callback function to receive the result of the createOffice operation. If none specified a Promise will be returned.
     * @callback module:api/OfficesApi~createOfficeCallback
     * @param {String} error Error message, if any.
     * @param {module:model/Office} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Create an office.
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/OfficeForCreate} optsOrCallback.body 
     * @param {module:api/OfficesApi~createOfficeCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/Office}
     */
    this.createOffice = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createOffice");
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
      var returnType = Office;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/offices', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteOffice operation. If none specified a Promise will be returned.
     * @callback module:api/OfficesApi~deleteOfficeCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Delete an office.
     * @param {String} accountId 
     * @param {Number} officeId 
     * @param {module:api/OfficesApi~deleteOfficeCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.deleteOffice = function(accountId, officeId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteOffice");
      }

      // verify the required parameter 'officeId' is set
      if (officeId === undefined || officeId === null) {
        throw new Error("Missing the required parameter 'officeId' when calling deleteOffice");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'officeId': officeId
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
      var returnType = null;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/offices/{officeId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getOffice operation. If none specified a Promise will be returned.
     * @callback module:api/OfficesApi~getOfficeCallback
     * @param {String} error Error message, if any.
     * @param {module:model/Office} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get information about the office with the given officeId.
     * @param {String} accountId 
     * @param {Number} officeId 
     * @param {module:api/OfficesApi~getOfficeCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/Office}
     */
    this.getOffice = function(accountId, officeId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getOffice");
      }

      // verify the required parameter 'officeId' is set
      if (officeId === undefined || officeId === null) {
        throw new Error("Missing the required parameter 'officeId' when calling getOffice");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'officeId': officeId
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
      var returnType = Office;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/offices/{officeId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getOffices operation. If none specified a Promise will be returned.
     * @callback module:api/OfficesApi~getOfficesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OfficeSummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get all 
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.count Number of offices to include in the response, (Default 100) (default to 100)
     * @param {Number} optsOrCallback.startPosition Position in the overall list of offices to begin results. (default to 0)
     * @param {Boolean} optsOrCallback.onlyAccessible When true, the response only includes offices accessible to the calling user. (default to false)
     * @param {String} optsOrCallback.search When specified, the response only includes offices whose names includes the specified search string.
     * @param {module:api/OfficesApi~getOfficesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OfficeSummaryList}
     */
    this.getOffices = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getOffices");
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
        'startPosition': optsOrCallback['startPosition'],
        'onlyAccessible': optsOrCallback['onlyAccessible'],
        'search': optsOrCallback['search']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = OfficeSummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/offices', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getReferenceCounts operation. If none specified a Promise will be returned.
     * @callback module:api/OfficesApi~getReferenceCountsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OfficeReferenceCountList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Lists the number of objects of each type that reference the office.
     * @param {String} accountId 
     * @param {Number} officeId 
     * @param {module:api/OfficesApi~getReferenceCountsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OfficeReferenceCountList}
     */
    this.getReferenceCounts = function(accountId, officeId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getReferenceCounts");
      }

      // verify the required parameter 'officeId' is set
      if (officeId === undefined || officeId === null) {
        throw new Error("Missing the required parameter 'officeId' when calling getReferenceCounts");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'officeId': officeId
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
      var returnType = OfficeReferenceCountList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/offices/{officeId}/reference_counts', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));