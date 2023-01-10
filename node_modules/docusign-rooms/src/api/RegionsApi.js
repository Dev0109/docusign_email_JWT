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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/Region', 'model/RegionReferenceCountList', 'model/RegionSummaryList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/Region'), require('../model/RegionReferenceCountList'), require('../model/RegionSummaryList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RegionsApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.Region, root.DocusignRooms.RegionReferenceCountList, root.DocusignRooms.RegionSummaryList);
  }
}(this, function(Configuration, ApiClient, ApiError, Region, RegionReferenceCountList, RegionSummaryList) {
  'use strict';

  /**
   * Regions service.
   * @module api/RegionsApi
   */

  /**
   * Constructs a new RegionsApi. 
   * @alias module:api/RegionsApi
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
     * (Optional) Callback function to receive the result of the createRegion operation. If none specified a Promise will be returned.
     * @callback module:api/RegionsApi~createRegionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/Region} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a new region for a company
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/Region} optsOrCallback.body 
     * @param {module:api/RegionsApi~createRegionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/Region}
     */
    this.createRegion = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createRegion");
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
      var returnType = Region;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/regions', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteRegion operation. If none specified a Promise will be returned.
     * @callback module:api/RegionsApi~deleteRegionCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Delete a region.
     * @param {String} accountId 
     * @param {Number} regionId Id of the desired region
     * @param {module:api/RegionsApi~deleteRegionCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.deleteRegion = function(accountId, regionId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteRegion");
      }

      // verify the required parameter 'regionId' is set
      if (regionId === undefined || regionId === null) {
        throw new Error("Missing the required parameter 'regionId' when calling deleteRegion");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'regionId': regionId
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
        '/v2/accounts/{accountId}/regions/{regionId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getRegion operation. If none specified a Promise will be returned.
     * @callback module:api/RegionsApi~getRegionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/Region} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get information about the region with the given regionId
     * @param {String} accountId 
     * @param {Number} regionId Id of the desired region
     * @param {module:api/RegionsApi~getRegionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/Region}
     */
    this.getRegion = function(accountId, regionId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getRegion");
      }

      // verify the required parameter 'regionId' is set
      if (regionId === undefined || regionId === null) {
        throw new Error("Missing the required parameter 'regionId' when calling getRegion");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'regionId': regionId
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
      var returnType = Region;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/regions/{regionId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getRegionReferenceCounts operation. If none specified a Promise will be returned.
     * @callback module:api/RegionsApi~getRegionReferenceCountsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/RegionReferenceCountList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get region reference counts.
     * @param {String} accountId 
     * @param {Number} regionId Id of the desired region
     * @param {module:api/RegionsApi~getRegionReferenceCountsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/RegionReferenceCountList}
     */
    this.getRegionReferenceCounts = function(accountId, regionId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getRegionReferenceCounts");
      }

      // verify the required parameter 'regionId' is set
      if (regionId === undefined || regionId === null) {
        throw new Error("Missing the required parameter 'regionId' when calling getRegionReferenceCounts");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'regionId': regionId
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
      var returnType = RegionReferenceCountList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/regions/{regionId}/reference_counts', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getRegions operation. If none specified a Promise will be returned.
     * @callback module:api/RegionsApi~getRegionsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/RegionSummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get account 
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.count Number of regions to include in the response, (Default 100). (default to 100)
     * @param {Number} optsOrCallback.startPosition Position in the overall list of regions to begin results. (default to 0)
     * @param {Boolean} optsOrCallback.managedOnly When true, the response only includes regions that the calling user can manage. (default to false)
     * @param {module:api/RegionsApi~getRegionsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/RegionSummaryList}
     */
    this.getRegions = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getRegions");
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
        'managedOnly': optsOrCallback['managedOnly']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = RegionSummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/regions', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));