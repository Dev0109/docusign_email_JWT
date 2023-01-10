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
	define(['Configuration', 'ApiClient', 'model/OrganizationAccountsRequest', 'model/OrganizationExportRequest', 'model/OrganizationExportResponse', 'model/OrganizationExportsResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/OrganizationAccountsRequest'), require('../model/OrganizationExportRequest'), require('../model/OrganizationExportResponse'), require('../model/OrganizationExportsResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.BulkExportsApi = factory(root.DocusignAdmin.Configuration, root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationAccountsRequest, root.DocusignAdmin.OrganizationExportRequest, root.DocusignAdmin.OrganizationExportResponse, root.DocusignAdmin.OrganizationExportsResponse);
  }
}(this, function(Configuration, ApiClient, OrganizationAccountsRequest, OrganizationExportRequest, OrganizationExportResponse, OrganizationExportsResponse) {
  'use strict';

  /**
   * BulkExports service.
   * @module api/BulkExportsApi
   */

  /**
   * Constructs a new BulkExportsApi. 
   * @alias module:api/BulkExportsApi
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
     * (Optional) Callback function to receive the result of the createAccountSettingsExport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~createAccountSettingsExportCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationExportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a  new Account Setting Export request.
     * Required scopes: account_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:model/OrganizationAccountsRequest} request Request body containing details about the accounts be compared
     * @param {module:api/BulkExportsApi~createAccountSettingsExportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationExportResponse}
     */
    this.createAccountSettingsExport = function(request, organizationId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createAccountSettingsExport");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling createAccountSettingsExport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId
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
      var returnType = OrganizationExportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/account_settings', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createUserListExport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~createUserListExportCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationExportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a new User List Export request.
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:model/OrganizationExportRequest} request Request body containing details about what is to be exported
     * @param {module:api/BulkExportsApi~createUserListExportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationExportResponse}
     */
    this.createUserListExport = function(request, organizationId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createUserListExport");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling createUserListExport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId
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
      var returnType = OrganizationExportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/user_list', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteAccountSettingsExport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~deleteAccountSettingsExportCallback
     * @param {String} error Error message, if any.
     * @param {Object} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes a single Account Settings Export request
     * Required scopes: account_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} exportId The export ID Guid for the request
     * @param {module:api/BulkExportsApi~deleteAccountSettingsExportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Object}
     */
    this.deleteAccountSettingsExport = function(organizationId, exportId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling deleteAccountSettingsExport");
      }

      // verify the required parameter 'exportId' is set
      if (exportId === undefined || exportId === null) {
        throw new Error("Missing the required parameter 'exportId' when calling deleteAccountSettingsExport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'exportId': exportId
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
      var returnType = Object;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/account_settings/{exportId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteUserListExport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~deleteUserListExportCallback
     * @param {String} error Error message, if any.
     * @param {Object} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes a single User List Export request
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} exportId The export ID Guid for the request
     * @param {module:api/BulkExportsApi~deleteUserListExportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Object}
     */
    this.deleteUserListExport = function(organizationId, exportId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling deleteUserListExport");
      }

      // verify the required parameter 'exportId' is set
      if (exportId === undefined || exportId === null) {
        throw new Error("Missing the required parameter 'exportId' when calling deleteUserListExport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'exportId': exportId
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
      var returnType = Object;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/user_list/{exportId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getAccountSettingsExport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~getAccountSettingsExportCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationExportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for a single Account Setting Export request
     * Required scopes: account_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} exportId The export ID Guid for the request
     * @param {module:api/BulkExportsApi~getAccountSettingsExportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationExportResponse}
     */
    this.getAccountSettingsExport = function(organizationId, exportId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getAccountSettingsExport");
      }

      // verify the required parameter 'exportId' is set
      if (exportId === undefined || exportId === null) {
        throw new Error("Missing the required parameter 'exportId' when calling getAccountSettingsExport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'exportId': exportId
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
      var returnType = OrganizationExportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/account_settings/{exportId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getAccountSettingsExports operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~getAccountSettingsExportsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationExportsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for Account Setting Export requests
     * Required scopes: account_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/BulkExportsApi~getAccountSettingsExportsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationExportsResponse}
     */
    this.getAccountSettingsExports = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getAccountSettingsExports");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId
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
      var returnType = OrganizationExportsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/account_settings', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getUserListExport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~getUserListExportCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationExportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for a single User List Export request
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} exportId The export ID Guid for the request
     * @param {module:api/BulkExportsApi~getUserListExportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationExportResponse}
     */
    this.getUserListExport = function(organizationId, exportId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getUserListExport");
      }

      // verify the required parameter 'exportId' is set
      if (exportId === undefined || exportId === null) {
        throw new Error("Missing the required parameter 'exportId' when calling getUserListExport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'exportId': exportId
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
      var returnType = OrganizationExportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/user_list/{exportId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getUserListExports operation. If none specified a Promise will be returned.
     * @callback module:api/BulkExportsApi~getUserListExportsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationExportsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns a list of existing User List Exports (requests and completed exports) and their details/metadata
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/BulkExportsApi~getUserListExportsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationExportsResponse}
     */
    this.getUserListExports = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getUserListExports");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId
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
      var returnType = OrganizationExportsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/exports/user_list', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));