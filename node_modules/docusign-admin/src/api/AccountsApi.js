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
	define(['Configuration', 'ApiClient', 'model/MemberGroupsResponse', 'model/OrganizationsResponse', 'model/PermissionsResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/MemberGroupsResponse'), require('../model/OrganizationsResponse'), require('../model/PermissionsResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.AccountsApi = factory(root.DocusignAdmin.Configuration, root.DocusignAdmin.ApiClient, root.DocusignAdmin.MemberGroupsResponse, root.DocusignAdmin.OrganizationsResponse, root.DocusignAdmin.PermissionsResponse);
  }
}(this, function(Configuration, ApiClient, MemberGroupsResponse, OrganizationsResponse, PermissionsResponse) {
  'use strict';

  /**
   * Accounts service.
   * @module api/AccountsApi
   */

  /**
   * Constructs a new AccountsApi. 
   * @alias module:api/AccountsApi
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
     * (Optional) Callback function to receive the result of the getGroups operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getGroupsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/MemberGroupsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the list of groups in an account.
     * Required scopes: group_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} accountId The account ID Guid
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.start Index of first item to include in the response  Default value: 0
     * @param {Number} optsOrCallback.take Page size of the response  Default value: 20
     * @param {Number} optsOrCallback.end Index of the last item to include in the response. Ignored if 'take' parameter is specfied
     * @param {module:api/AccountsApi~getGroupsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/MemberGroupsResponse}
     */
    this.getGroups = function(organizationId, accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getGroups");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getGroups");
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
        'start': optsOrCallback['start'],
        'take': optsOrCallback['take'],
        'end': optsOrCallback['end']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = MemberGroupsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/accounts/{accountId}/groups', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getOrganizations operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getOrganizationsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the list of organizations of which the authenticated user is a member.
     * Required scopes: organization_read
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.mode Specifies how to select the organizations. Values: org_admin - will return organizations for which the user is an admin; account_membership: will return organizations that contain an account of which the user is a member  Default value: org_admin
     * @param {module:api/AccountsApi~getOrganizationsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationsResponse}
     */
    this.getOrganizations = function(optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

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
        'mode': optsOrCallback['mode']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = OrganizationsResponse;

      return this.apiClient.callApi(
        '/v2/organizations', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getPermissions operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getPermissionsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/PermissionsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns the list of permission profiles in an account.
     * Required scopes: permission_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} accountId The account ID Guid
     * @param {module:api/AccountsApi~getPermissionsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/PermissionsResponse}
     */
    this.getPermissions = function(organizationId, accountId, callback) {
      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getPermissions");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getPermissions");
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
      var returnType = PermissionsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/accounts/{accountId}/permissions', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));