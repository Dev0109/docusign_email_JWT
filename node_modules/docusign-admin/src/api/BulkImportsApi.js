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
	define(['Configuration', 'ApiClient', 'model/OrganizationAccountSettingsImportResponse', 'model/OrganizationImportResponse', 'model/OrganizationImportsResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/OrganizationAccountSettingsImportResponse'), require('../model/OrganizationImportResponse'), require('../model/OrganizationImportsResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.BulkImportsApi = factory(root.DocusignAdmin.Configuration, root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationAccountSettingsImportResponse, root.DocusignAdmin.OrganizationImportResponse, root.DocusignAdmin.OrganizationImportsResponse);
  }
}(this, function(Configuration, ApiClient, OrganizationAccountSettingsImportResponse, OrganizationImportResponse, OrganizationImportsResponse) {
  'use strict';

  /**
   * BulkImports service.
   * @module api/BulkImportsApi
   */

  /**
   * Constructs a new BulkImportsApi. 
   * @alias module:api/BulkImportsApi
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
     * (Optional) Callback function to receive the result of the addBulkAccountSettingsImport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~addBulkAccountSettingsImportCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationAccountSettingsImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a new account settings import request.
     * Required scopes: account_write
     * @param {String} organizationId The organization ID Guid
     * @param {Object} fileCsv CSV file.
     * @param {module:api/BulkImportsApi~addBulkAccountSettingsImportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationAccountSettingsImportResponse}
     */
    this.addBulkAccountSettingsImport = function(organizationId, fileCsv, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling addBulkAccountSettingsImport");
      }

      // verify the required parameter 'fileCsv' is set
      if (fileCsv === undefined || fileCsv === null) {
        throw new Error("Missing the required parameter 'fileCsv' when calling addBulkAccountSettingsImport");
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
        'file.csv': fileCsv
      };

      var authNames = [];
      var contentTypes = ['multipart/form-data'];
      var accepts = ['application/json'];
      var returnType = OrganizationAccountSettingsImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/account_settings', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createBulkImportAddUsersRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~createBulkImportAddUsersRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Import request for adding users to accounts within the organization.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {Object} fileCsv CSV file.
     * @param {module:api/BulkImportsApi~createBulkImportAddUsersRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.createBulkImportAddUsersRequest = function(organizationId, fileCsv, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createBulkImportAddUsersRequest");
      }

      // verify the required parameter 'fileCsv' is set
      if (fileCsv === undefined || fileCsv === null) {
        throw new Error("Missing the required parameter 'fileCsv' when calling createBulkImportAddUsersRequest");
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
        'file.csv': fileCsv
      };

      var authNames = [];
      var contentTypes = ['multipart/form-data'];
      var accepts = ['application/json'];
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users/add', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createBulkImportCloseUsersRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~createBulkImportCloseUsersRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Closes the Bulk User Import request
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/BulkImportsApi~createBulkImportCloseUsersRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.createBulkImportCloseUsersRequest = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createBulkImportCloseUsersRequest");
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
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users/close', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createBulkImportExternalCloseUsersRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~createBulkImportExternalCloseUsersRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Closes memberships which are not in an account which is part of the organization, but which do have email addresses which are @ a verified reserved web domain which belongs to the organization
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/BulkImportsApi~createBulkImportExternalCloseUsersRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.createBulkImportExternalCloseUsersRequest = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createBulkImportExternalCloseUsersRequest");
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
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users/close_external', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createBulkImportSingleAccountAddUsersRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~createBulkImportSingleAccountAddUsersRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Import request for adding user to a single account within the organization. Allows upload of user information without requiring an AccountId column
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} accountId The account ID Guid
     * @param {Object} fileCsv CSV file.
     * @param {module:api/BulkImportsApi~createBulkImportSingleAccountAddUsersRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.createBulkImportSingleAccountAddUsersRequest = function(organizationId, accountId, fileCsv, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createBulkImportSingleAccountAddUsersRequest");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createBulkImportSingleAccountAddUsersRequest");
      }

      // verify the required parameter 'fileCsv' is set
      if (fileCsv === undefined || fileCsv === null) {
        throw new Error("Missing the required parameter 'fileCsv' when calling createBulkImportSingleAccountAddUsersRequest");
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
        'file.csv': fileCsv
      };

      var authNames = [];
      var contentTypes = ['multipart/form-data'];
      var accepts = ['application/json'];
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/accounts/{accountId}/imports/bulk_users/add', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createBulkImportSingleAccountUpdateUsersRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~createBulkImportSingleAccountUpdateUsersRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Import request for updating users for a single account within the organization. Allows upload of user information without requiring an AccountId column
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} accountId The account ID Guid
     * @param {Object} fileCsv CSV file.
     * @param {module:api/BulkImportsApi~createBulkImportSingleAccountUpdateUsersRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.createBulkImportSingleAccountUpdateUsersRequest = function(organizationId, accountId, fileCsv, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createBulkImportSingleAccountUpdateUsersRequest");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createBulkImportSingleAccountUpdateUsersRequest");
      }

      // verify the required parameter 'fileCsv' is set
      if (fileCsv === undefined || fileCsv === null) {
        throw new Error("Missing the required parameter 'fileCsv' when calling createBulkImportSingleAccountUpdateUsersRequest");
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
        'file.csv': fileCsv
      };

      var authNames = [];
      var contentTypes = ['multipart/form-data'];
      var accepts = ['application/json'];
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/accounts/{accountId}/imports/bulk_users/update', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createBulkImportUpdateUsersRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~createBulkImportUpdateUsersRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Import request for updating users to accounts within the organization.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {Object} fileCsv CSV file.
     * @param {module:api/BulkImportsApi~createBulkImportUpdateUsersRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.createBulkImportUpdateUsersRequest = function(organizationId, fileCsv, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createBulkImportUpdateUsersRequest");
      }

      // verify the required parameter 'fileCsv' is set
      if (fileCsv === undefined || fileCsv === null) {
        throw new Error("Missing the required parameter 'fileCsv' when calling createBulkImportUpdateUsersRequest");
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
        'file.csv': fileCsv
      };

      var authNames = [];
      var contentTypes = ['multipart/form-data'];
      var accepts = ['application/json'];
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users/update', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteBulkAccountSettingsImport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~deleteBulkAccountSettingsImportCallback
     * @param {String} error Error message, if any.
     * @param {Object} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes a Bulk Account Settings Import request
     * Required scopes: account_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} importId The import ID Guid for the request
     * @param {module:api/BulkImportsApi~deleteBulkAccountSettingsImportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Object}
     */
    this.deleteBulkAccountSettingsImport = function(organizationId, importId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling deleteBulkAccountSettingsImport");
      }

      // verify the required parameter 'importId' is set
      if (importId === undefined || importId === null) {
        throw new Error("Missing the required parameter 'importId' when calling deleteBulkAccountSettingsImport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'importId': importId
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
        '/v2/organizations/{organizationId}/imports/account_settings/{importId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteBulkUserImport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~deleteBulkUserImportCallback
     * @param {String} error Error message, if any.
     * @param {Object} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes a User Import request
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} importId The import ID Guid for the request
     * @param {module:api/BulkImportsApi~deleteBulkUserImportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Object}
     */
    this.deleteBulkUserImport = function(organizationId, importId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling deleteBulkUserImport");
      }

      // verify the required parameter 'importId' is set
      if (importId === undefined || importId === null) {
        throw new Error("Missing the required parameter 'importId' when calling deleteBulkUserImport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'importId': importId
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
        '/v2/organizations/{organizationId}/imports/bulk_users/{importId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getBulkAccountSettingsImport operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~getBulkAccountSettingsImportCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationAccountSettingsImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for a Bulk Account Settings Import request
     * Required scopes: account_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} importId The import ID Guid for the request
     * @param {module:api/BulkImportsApi~getBulkAccountSettingsImportCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationAccountSettingsImportResponse}
     */
    this.getBulkAccountSettingsImport = function(organizationId, importId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getBulkAccountSettingsImport");
      }

      // verify the required parameter 'importId' is set
      if (importId === undefined || importId === null) {
        throw new Error("Missing the required parameter 'importId' when calling getBulkAccountSettingsImport");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'importId': importId
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
      var returnType = OrganizationAccountSettingsImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/account_settings/{importId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getBulkAccountSettingsImports operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~getBulkAccountSettingsImportsCallback
     * @param {String} error Error message, if any.
     * @param {Array.<module:model/OrganizationAccountSettingsImportResponse>} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for Bulk Account Settings Import requests in the organization
     * Required scopes: account_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/BulkImportsApi~getBulkAccountSettingsImportsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Array.<module:model/OrganizationAccountSettingsImportResponse>}
     */
    this.getBulkAccountSettingsImports = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getBulkAccountSettingsImports");
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
      var returnType = [OrganizationAccountSettingsImportResponse];

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/account_settings', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getBulkUserImportCSV operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~getBulkUserImportCSVCallback
     * @param {String} error Error message, if any.
     * @param {Object} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns a text/csv file with user details for a User Import request
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} importId The import ID Guid for the request
     * @param {module:api/BulkImportsApi~getBulkUserImportCSVCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Object}
     */
    this.getBulkUserImportCSV = function(organizationId, importId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getBulkUserImportCSV");
      }

      // verify the required parameter 'importId' is set
      if (importId === undefined || importId === null) {
        throw new Error("Missing the required parameter 'importId' when calling getBulkUserImportCSV");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'importId': importId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['text/csv'];
      var returnType = Object;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users/{importId}/results_csv', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getBulkUserImportRequest operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~getBulkUserImportRequestCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for a User Import request
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} importId The import ID Guid for the request
     * @param {module:api/BulkImportsApi~getBulkUserImportRequestCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportResponse}
     */
    this.getBulkUserImportRequest = function(organizationId, importId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getBulkUserImportRequest");
      }

      // verify the required parameter 'importId' is set
      if (importId === undefined || importId === null) {
        throw new Error("Missing the required parameter 'importId' when calling getBulkUserImportRequest");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'importId': importId
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
      var returnType = OrganizationImportResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users/{importId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getBulkUserImportRequests operation. If none specified a Promise will be returned.
     * @callback module:api/BulkImportsApi~getBulkUserImportRequestsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationImportsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the details/metadata for Bulk User Import requests in the organization
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {module:api/BulkImportsApi~getBulkUserImportRequestsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationImportsResponse}
     */
    this.getBulkUserImportRequests = function(organizationId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getBulkUserImportRequests");
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
      var returnType = OrganizationImportsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/imports/bulk_users', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));