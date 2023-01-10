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
	define(['Configuration', 'ApiClient', 'model/AddDSGroupAndUsersResponse', 'model/DSGroupAddRequest', 'model/DSGroupAndUsersResponse', 'model/DSGroupListResponse', 'model/DSGroupResponse', 'model/DSGroupUsersAddRequest', 'model/DSGroupUsersRemoveRequest', 'model/RemoveDSGroupUsersResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/AddDSGroupAndUsersResponse'), require('../model/DSGroupAddRequest'), require('../model/DSGroupAndUsersResponse'), require('../model/DSGroupListResponse'), require('../model/DSGroupResponse'), require('../model/DSGroupUsersAddRequest'), require('../model/DSGroupUsersRemoveRequest'), require('../model/RemoveDSGroupUsersResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DSGroupsApi = factory(root.DocusignAdmin.Configuration, root.DocusignAdmin.ApiClient, root.DocusignAdmin.AddDSGroupAndUsersResponse, root.DocusignAdmin.DSGroupAddRequest, root.DocusignAdmin.DSGroupAndUsersResponse, root.DocusignAdmin.DSGroupListResponse, root.DocusignAdmin.DSGroupResponse, root.DocusignAdmin.DSGroupUsersAddRequest, root.DocusignAdmin.DSGroupUsersRemoveRequest, root.DocusignAdmin.RemoveDSGroupUsersResponse);
  }
}(this, function(Configuration, ApiClient, AddDSGroupAndUsersResponse, DSGroupAddRequest, DSGroupAndUsersResponse, DSGroupListResponse, DSGroupResponse, DSGroupUsersAddRequest, DSGroupUsersRemoveRequest, RemoveDSGroupUsersResponse) {
  'use strict';

  /**
   * DSGroups service.
   * @module api/DSGroupsApi
   */

  /**
   * Constructs a new DSGroupsApi. 
   * @alias module:api/DSGroupsApi
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
     * (Optional) Callback function to receive the result of the addDSGroup operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~addDSGroupCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DSGroupResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Add a new DSGroup
     * Required scopes: user_write
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {module:model/DSGroupAddRequest} addRequest Add DSGroup request object
     * @param {module:api/DSGroupsApi~addDSGroupCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DSGroupResponse}
     */
    this.addDSGroup = function(addRequest, organizationId, accountId, callback) {
      var postBody = addRequest;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling addDSGroup");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling addDSGroup");
      }

      // verify the required parameter 'addRequest' is set
      if (addRequest === undefined || addRequest === null) {
        throw new Error("Missing the required parameter 'addRequest' when calling addDSGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId
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
      var returnType = DSGroupResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the addDSGroupUsers operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~addDSGroupUsersCallback
     * @param {String} error Error message, if any.
     * @param {module:model/AddDSGroupAndUsersResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Add list of users to a DSGroup
     * Required scopes: user_write
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {String} dsGroupId The DSGroup ID GUID
     * @param {module:model/DSGroupUsersAddRequest} dSGroupUsersAddRequest Add DSGroup users request object
     * @param {module:api/DSGroupsApi~addDSGroupUsersCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/AddDSGroupAndUsersResponse}
     */
    this.addDSGroupUsers = function(dSGroupUsersAddRequest, organizationId, accountId, dsGroupId, callback) {
      var postBody = dSGroupUsersAddRequest;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling addDSGroupUsers");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling addDSGroupUsers");
      }

      // verify the required parameter 'dsGroupId' is set
      if (dsGroupId === undefined || dsGroupId === null) {
        throw new Error("Missing the required parameter 'dsGroupId' when calling addDSGroupUsers");
      }

      // verify the required parameter 'dSGroupUsersAddRequest' is set
      if (dSGroupUsersAddRequest === undefined || dSGroupUsersAddRequest === null) {
        throw new Error("Missing the required parameter 'dSGroupUsersAddRequest' when calling addDSGroupUsers");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId,
        'dsGroupId': dsGroupId
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
      var returnType = AddDSGroupAndUsersResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups/{dsGroupId}/users', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteDSGroup operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~deleteDSGroupCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Delete a DSGroup
     * Required scopes: user_write
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {String} dsGroupId The DSGroup ID GUID
     * @param {module:api/DSGroupsApi~deleteDSGroupCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.deleteDSGroup = function(organizationId, accountId, dsGroupId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling deleteDSGroup");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteDSGroup");
      }

      // verify the required parameter 'dsGroupId' is set
      if (dsGroupId === undefined || dsGroupId === null) {
        throw new Error("Missing the required parameter 'dsGroupId' when calling deleteDSGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId,
        'dsGroupId': dsGroupId
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
      var returnType = null;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups/{dsGroupId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getDSGroup operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~getDSGroupCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DSGroupResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get list of DSGroup
     * Required scopes: user_read
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {String} dsGroupId The dsGroup ID GUID
     * @param {module:api/DSGroupsApi~getDSGroupCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DSGroupResponse}
     */
    this.getDSGroup = function(organizationId, accountId, dsGroupId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getDSGroup");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getDSGroup");
      }

      // verify the required parameter 'dsGroupId' is set
      if (dsGroupId === undefined || dsGroupId === null) {
        throw new Error("Missing the required parameter 'dsGroupId' when calling getDSGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId,
        'dsGroupId': dsGroupId
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
      var returnType = DSGroupResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups/{dsGroupId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getDSGroupUsers operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~getDSGroupUsersCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DSGroupAndUsersResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get list of users in a DSGroup
     * Required scopes: user_read
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {String} dsGroupId The DSGroup ID GUID
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.page Start page of dsgroup users
     * @param {Number} optsOrCallback.pageSize Page size of dsgroup users
     * @param {module:api/DSGroupsApi~getDSGroupUsersCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DSGroupAndUsersResponse}
     */
    this.getDSGroupUsers = function(organizationId, accountId, dsGroupId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getDSGroupUsers");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getDSGroupUsers");
      }

      // verify the required parameter 'dsGroupId' is set
      if (dsGroupId === undefined || dsGroupId === null) {
        throw new Error("Missing the required parameter 'dsGroupId' when calling getDSGroupUsers");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId,
        'dsGroupId': dsGroupId
      };
      var queryParams = {
        'page': optsOrCallback['page'],
        'page_size': optsOrCallback['pageSize']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = DSGroupAndUsersResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups/{dsGroupId}/users', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getDSGroups operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~getDSGroupsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DSGroupListResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get list of DSGroups
     * Required scopes: user_read
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.page Start page of dsgroups
     * @param {Number} optsOrCallback.pageSize Page size of dsgroups
     * @param {module:api/DSGroupsApi~getDSGroupsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DSGroupListResponse}
     */
    this.getDSGroups = function(organizationId, accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getDSGroups");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getDSGroups");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId
      };
      var queryParams = {
        'page': optsOrCallback['page'],
        'page_size': optsOrCallback['pageSize']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = DSGroupListResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the removeDSGroupUsers operation. If none specified a Promise will be returned.
     * @callback module:api/DSGroupsApi~removeDSGroupUsersCallback
     * @param {String} error Error message, if any.
     * @param {module:model/RemoveDSGroupUsersResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Remove users from a DSGroup
     * Required scopes: user_write
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {String} dsGroupId The DSGroup ID GUID
     * @param {module:model/DSGroupUsersRemoveRequest} dSGroupUsersRemoveRequest Remove DSGroup users request object
     * @param {module:api/DSGroupsApi~removeDSGroupUsersCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/RemoveDSGroupUsersResponse}
     */
    this.removeDSGroupUsers = function(dSGroupUsersRemoveRequest, organizationId, accountId, dsGroupId, callback) {
      var postBody = dSGroupUsersRemoveRequest;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling removeDSGroupUsers");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling removeDSGroupUsers");
      }

      // verify the required parameter 'dsGroupId' is set
      if (dsGroupId === undefined || dsGroupId === null) {
        throw new Error("Missing the required parameter 'dsGroupId' when calling removeDSGroupUsers");
      }

      // verify the required parameter 'dSGroupUsersRemoveRequest' is set
      if (dSGroupUsersRemoveRequest === undefined || dSGroupUsersRemoveRequest === null) {
        throw new Error("Missing the required parameter 'dSGroupUsersRemoveRequest' when calling removeDSGroupUsers");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'accountId': accountId,
        'dsGroupId': dsGroupId
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
      var returnType = RemoveDSGroupUsersResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/dsgroups/{dsGroupId}/users', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));