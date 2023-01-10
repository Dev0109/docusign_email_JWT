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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/RoomTemplatesSummaryList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/RoomTemplatesSummaryList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RoomTemplatesApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.RoomTemplatesSummaryList);
  }
}(this, function(Configuration, ApiClient, ApiError, RoomTemplatesSummaryList) {
  'use strict';

  /**
   * RoomTemplates service.
   * @module api/RoomTemplatesApi
   */

  /**
   * Constructs a new RoomTemplatesApi. 
   * @alias module:api/RoomTemplatesApi
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
     * (Optional) Callback function to receive the result of the getRoomTemplates operation. If none specified a Promise will be returned.
     * @callback module:api/RoomTemplatesApi~getRoomTemplatesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/RoomTemplatesSummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns all room templates that the active user has access to
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.officeId Get all room templates you have access to for this office. Response includes Company and Region level  If onlyAssignable is true, and no officeId is provided, user's default office is assumed.
     * @param {Boolean} optsOrCallback.onlyAssignable Get list of templates you have access to. Default value false. (default to false)
     * @param {Boolean} optsOrCallback.onlyEnabled When set to true, only returns room templates that are not disabled. (default to true)
     * @param {Number} optsOrCallback.count Number of room templates to return. Defaults to the maximum which is 100. (default to 100)
     * @param {Number} optsOrCallback.startPosition Position of the first item in the total results. Defaults to 0. (default to 0)
     * @param {module:api/RoomTemplatesApi~getRoomTemplatesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/RoomTemplatesSummaryList}
     */
    this.getRoomTemplates = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getRoomTemplates");
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
        'officeId': optsOrCallback['officeId'],
        'onlyAssignable': optsOrCallback['onlyAssignable'],
        'onlyEnabled': optsOrCallback['onlyEnabled'],
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
      var returnType = RoomTemplatesSummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/room_templates', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));