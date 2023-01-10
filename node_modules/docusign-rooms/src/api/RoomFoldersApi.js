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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/RoomFolderList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/RoomFolderList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RoomFoldersApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.RoomFolderList);
  }
}(this, function(Configuration, ApiClient, ApiError, RoomFolderList) {
  'use strict';

  /**
   * RoomFolders service.
   * @module api/RoomFoldersApi
   */

  /**
   * Constructs a new RoomFoldersApi. 
   * @alias module:api/RoomFoldersApi
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
     * (Optional) Callback function to receive the result of the getRoomFolders operation. If none specified a Promise will be returned.
     * @callback module:api/RoomFoldersApi~getRoomFoldersCallback
     * @param {String} error Error message, if any.
     * @param {module:model/RoomFolderList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets room folders accessible to the calling user.
     * @param {String} accountId 
     * @param {Number} roomId The room id from which to retrieve folders.
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.startPosition Position of the first item in the total results. Defaults to 0. (default to 0)
     * @param {Number} optsOrCallback.count Number of room folders to return. Defaults to the maximum which is 100. (default to 100)
     * @param {module:api/RoomFoldersApi~getRoomFoldersCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/RoomFolderList}
     */
    this.getRoomFolders = function(accountId, roomId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getRoomFolders");
      }

      // verify the required parameter 'roomId' is set
      if (roomId === undefined || roomId === null) {
        throw new Error("Missing the required parameter 'roomId' when calling getRoomFolders");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'roomId': roomId
      };
      var queryParams = {
        'startPosition': optsOrCallback['startPosition'],
        'count': optsOrCallback['count']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = RoomFolderList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/rooms/{roomId}/room_folders', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));