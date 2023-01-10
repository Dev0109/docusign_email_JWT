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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/TaskList', 'model/TaskListForCreate', 'model/TaskListSummaryList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/TaskList'), require('../model/TaskListForCreate'), require('../model/TaskListSummaryList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.TaskListsApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.TaskList, root.DocusignRooms.TaskListForCreate, root.DocusignRooms.TaskListSummaryList);
  }
}(this, function(Configuration, ApiClient, ApiError, TaskList, TaskListForCreate, TaskListSummaryList) {
  'use strict';

  /**
   * TaskLists service.
   * @module api/TaskListsApi
   */

  /**
   * Constructs a new TaskListsApi. 
   * @alias module:api/TaskListsApi
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
     * (Optional) Callback function to receive the result of the createTaskList operation. If none specified a Promise will be returned.
     * @callback module:api/TaskListsApi~createTaskListCallback
     * @param {String} error Error message, if any.
     * @param {module:model/TaskList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Add a task list to a room based on a task list template.
     * @param {String} accountId 
     * @param {Number} roomId Room ID.
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/TaskListForCreate} optsOrCallback.body 
     * @param {module:api/TaskListsApi~createTaskListCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/TaskList}
     */
    this.createTaskList = function(accountId, roomId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createTaskList");
      }

      // verify the required parameter 'roomId' is set
      if (roomId === undefined || roomId === null) {
        throw new Error("Missing the required parameter 'roomId' when calling createTaskList");
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
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = ['application/json-patch+json', 'application/json', 'text/json', 'application/_*+json'];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = TaskList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/rooms/{roomId}/task_lists', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteTaskList operation. If none specified a Promise will be returned.
     * @callback module:api/TaskListsApi~deleteTaskListCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes a task list. If there are attached documents they will remain in the associated 
     * @param {String} accountId 
     * @param {Number} taskListId Task List ID
     * @param {module:api/TaskListsApi~deleteTaskListCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.deleteTaskList = function(accountId, taskListId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteTaskList");
      }

      // verify the required parameter 'taskListId' is set
      if (taskListId === undefined || taskListId === null) {
        throw new Error("Missing the required parameter 'taskListId' when calling deleteTaskList");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'taskListId': taskListId
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
        '/v2/accounts/{accountId}/task_lists/{taskListId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getTaskLists operation. If none specified a Promise will be returned.
     * @callback module:api/TaskListsApi~getTaskListsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/TaskListSummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the summary for all viewable task lists in a 
     * @param {String} accountId 
     * @param {Number} roomId Room ID
     * @param {module:api/TaskListsApi~getTaskListsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/TaskListSummaryList}
     */
    this.getTaskLists = function(accountId, roomId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getTaskLists");
      }

      // verify the required parameter 'roomId' is set
      if (roomId === undefined || roomId === null) {
        throw new Error("Missing the required parameter 'roomId' when calling getTaskLists");
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
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = TaskListSummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/rooms/{roomId}/task_lists', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));