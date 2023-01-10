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
	define(['Configuration', 'ApiClient', 'model/AddUserResponse', 'model/DeleteMembershipsRequest', 'model/DeleteMembershipsResponse', 'model/DeleteResponse', 'model/DeleteUserIdentityRequest', 'model/ForceActivateMembershipRequest', 'model/NewAccountUserRequest', 'model/NewMultiProductUserAddRequest', 'model/NewUserRequest', 'model/NewUserResponse', 'model/OrganizationUsersResponse', 'model/UpdateResponse', 'model/UpdateUsersEmailRequest', 'model/UpdateUsersRequest', 'model/UsersDrilldownResponse', 'model/UsersUpdateResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/AddUserResponse'), require('../model/DeleteMembershipsRequest'), require('../model/DeleteMembershipsResponse'), require('../model/DeleteResponse'), require('../model/DeleteUserIdentityRequest'), require('../model/ForceActivateMembershipRequest'), require('../model/NewAccountUserRequest'), require('../model/NewMultiProductUserAddRequest'), require('../model/NewUserRequest'), require('../model/NewUserResponse'), require('../model/OrganizationUsersResponse'), require('../model/UpdateResponse'), require('../model/UpdateUsersEmailRequest'), require('../model/UpdateUsersRequest'), require('../model/UsersDrilldownResponse'), require('../model/UsersUpdateResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UsersApi = factory(root.DocusignAdmin.Configuration, root.DocusignAdmin.ApiClient, root.DocusignAdmin.AddUserResponse, root.DocusignAdmin.DeleteMembershipsRequest, root.DocusignAdmin.DeleteMembershipsResponse, root.DocusignAdmin.DeleteResponse, root.DocusignAdmin.DeleteUserIdentityRequest, root.DocusignAdmin.ForceActivateMembershipRequest, root.DocusignAdmin.NewAccountUserRequest, root.DocusignAdmin.NewMultiProductUserAddRequest, root.DocusignAdmin.NewUserRequest, root.DocusignAdmin.NewUserResponse, root.DocusignAdmin.OrganizationUsersResponse, root.DocusignAdmin.UpdateResponse, root.DocusignAdmin.UpdateUsersEmailRequest, root.DocusignAdmin.UpdateUsersRequest, root.DocusignAdmin.UsersDrilldownResponse, root.DocusignAdmin.UsersUpdateResponse);
  }
}(this, function(Configuration, ApiClient, AddUserResponse, DeleteMembershipsRequest, DeleteMembershipsResponse, DeleteResponse, DeleteUserIdentityRequest, ForceActivateMembershipRequest, NewAccountUserRequest, NewMultiProductUserAddRequest, NewUserRequest, NewUserResponse, OrganizationUsersResponse, UpdateResponse, UpdateUsersEmailRequest, UpdateUsersRequest, UsersDrilldownResponse, UsersUpdateResponse) {
  'use strict';

  /**
   * Users service.
   * @module api/UsersApi
   */

  /**
   * Constructs a new UsersApi. 
   * @alias module:api/UsersApi
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
     * (Optional) Callback function to receive the result of the activateMembership operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~activateMembershipCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UpdateResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Activates user memberships
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} userId The user ID Guid
     * @param {String} membershipId The membership ID Guid
     * @param {module:model/ForceActivateMembershipRequest} request Additional details about the user's membership
     * @param {module:api/UsersApi~activateMembershipCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UpdateResponse}
     */
    this.activateMembership = function(request, organizationId, userId, membershipId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling activateMembership");
      }

      // verify the required parameter 'userId' is set
      if (userId === undefined || userId === null) {
        throw new Error("Missing the required parameter 'userId' when calling activateMembership");
      }

      // verify the required parameter 'membershipId' is set
      if (membershipId === undefined || membershipId === null) {
        throw new Error("Missing the required parameter 'membershipId' when calling activateMembership");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling activateMembership");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'userId': userId,
        'membershipId': membershipId
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
      var returnType = UpdateResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users/{userId}/memberships/{membershipId}', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the addOrUpdateUser operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~addOrUpdateUserCallback
     * @param {String} error Error message, if any.
     * @param {module:model/AddUserResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates and updates a multi-product user
     * Required scopes: user_write
     * @param {String} organizationId The organization ID GUID
     * @param {String} accountId The account ID GUID
     * @param {module:model/NewMultiProductUserAddRequest} request The request object
     * @param {module:api/UsersApi~addOrUpdateUserCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/AddUserResponse}
     */
    this.addOrUpdateUser = function(request, organizationId, accountId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling addOrUpdateUser");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling addOrUpdateUser");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling addOrUpdateUser");
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
      var returnType = AddUserResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/accounts/{accountId}/users', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the addUsers operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~addUsersCallback
     * @param {String} error Error message, if any.
     * @param {module:model/NewUserResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Adds users to an account.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} accountId The account ID Guid
     * @param {module:model/NewAccountUserRequest} request The details for the users to add to the account
     * @param {module:api/UsersApi~addUsersCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/NewUserResponse}
     */
    this.addUsers = function(request, organizationId, accountId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling addUsers");
      }

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling addUsers");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling addUsers");
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
      var returnType = NewUserResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/accounts/{accountId}/users', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the closeMemberships operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~closeMembershipsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DeleteMembershipsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Closes a user's memberships.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} userId The user ID Guid
     * @param {module:model/DeleteMembershipsRequest} request The details about which membership to close
     * @param {module:api/UsersApi~closeMembershipsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DeleteMembershipsResponse}
     */
    this.closeMemberships = function(request, organizationId, userId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling closeMemberships");
      }

      // verify the required parameter 'userId' is set
      if (userId === undefined || userId === null) {
        throw new Error("Missing the required parameter 'userId' when calling closeMemberships");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling closeMemberships");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'userId': userId
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
      var returnType = DeleteMembershipsResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users/{userId}/accounts', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createUser operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~createUserCallback
     * @param {String} error Error message, if any.
     * @param {module:model/NewUserResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a new user
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {module:model/NewUserRequest} request Details about the user to be added
     * @param {module:api/UsersApi~createUserCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/NewUserResponse}
     */
    this.createUser = function(request, organizationId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling createUser");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling createUser");
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
      var returnType = NewUserResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteIdentities operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~deleteIdentitiesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/DeleteResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes user identities.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {String} userId The user ID Guid
     * @param {module:model/DeleteUserIdentityRequest} requestModel The details for the user identities to be deleted
     * @param {module:api/UsersApi~deleteIdentitiesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/DeleteResponse}
     */
    this.deleteIdentities = function(requestModel, organizationId, userId, callback) {
      var postBody = requestModel;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling deleteIdentities");
      }

      // verify the required parameter 'userId' is set
      if (userId === undefined || userId === null) {
        throw new Error("Missing the required parameter 'userId' when calling deleteIdentities");
      }

      // verify the required parameter 'requestModel' is set
      if (requestModel === undefined || requestModel === null) {
        throw new Error("Missing the required parameter 'requestModel' when calling deleteIdentities");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'userId': userId
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
      var returnType = DeleteResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users/{userId}/identities', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getUserDSProfile operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~getUserDSProfileCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UsersDrilldownResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns user information using the userId for lookup.
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {String} userId The user ID Guid
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Boolean} optsOrCallback.sort Sorts user information by account name ascending
     * @param {module:api/UsersApi~getUserDSProfileCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UsersDrilldownResponse}
     */
    this.getUserDSProfile = function(organizationId, userId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getUserDSProfile");
      }

      // verify the required parameter 'userId' is set
      if (userId === undefined || userId === null) {
        throw new Error("Missing the required parameter 'userId' when calling getUserDSProfile");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'organizationId': organizationId,
        'userId': userId
      };
      var queryParams = {
        'sort': optsOrCallback['sort']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = UsersDrilldownResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/users/{userId}/dsprofile', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getUserDSProfilesByEmail operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~getUserDSProfilesByEmailCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UsersDrilldownResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns DS user profile information.
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.email The email address of the user
     * @param {Boolean} optsOrCallback.sort Sorts user information by account name ascending
     * @param {module:api/UsersApi~getUserDSProfilesByEmailCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UsersDrilldownResponse}
     */
    this.getUserDSProfilesByEmail = function(organizationId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getUserDSProfilesByEmail");
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
        'email': optsOrCallback['email'],
        'sort': optsOrCallback['sort']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = UsersDrilldownResponse;

      return this.apiClient.callApi(
        '/v2.1/organizations/{organizationId}/users/dsprofile', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getUserProfiles operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~getUserProfilesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UsersDrilldownResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns user information.
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.email The email address
     * @param {module:api/UsersApi~getUserProfilesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UsersDrilldownResponse}
     */
    this.getUserProfiles = function(organizationId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getUserProfiles");
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
        'email': optsOrCallback['email']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = UsersDrilldownResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users/profile', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getUsers operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~getUsersCallback
     * @param {String} error Error message, if any.
     * @param {module:model/OrganizationUsersResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Returns information about the users in the organization
     * Required scopes: user_read
     * @param {String} organizationId The organization ID Guid
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.start Index of first item to include in the response  Default value: 0
     * @param {Number} optsOrCallback.take Page size of the response  Default value: 20
     * @param {Number} optsOrCallback.end Index of the last item to include in the response. Ignored if 'take' parameter is specfied
     * @param {String} optsOrCallback.email Email address of the desired user. At least one of email, account_id or organization_reserved_domain_id must be specified.
     * @param {String} optsOrCallback.emailUserNameLike Selects users by pattern matching on the user's email address
     * @param {String} optsOrCallback.status Select users based on user status
     * @param {String} optsOrCallback.membershipStatus Select users based on membership status
     * @param {String} optsOrCallback.accountId Select users that are members of the specified account. At least one of email, account_id or organization_reserved_domain_id must be specified.
     * @param {String} optsOrCallback.organizationReservedDomainId Select users that are in the specified domain. At least one of email, account_id or organization_reserved_domain_id must be specified.
     * @param {String} optsOrCallback.lastModifiedSince Select users whose data have been modified since the date specified;  account_id or organization_reserved_domain_id must be specified.
     * @param {module:api/UsersApi~getUsersCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/OrganizationUsersResponse}
     */
    this.getUsers = function(organizationId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling getUsers");
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
        'start': optsOrCallback['start'],
        'take': optsOrCallback['take'],
        'end': optsOrCallback['end'],
        'email': optsOrCallback['email'],
        'email_user_name_like': optsOrCallback['emailUserNameLike'],
        'status': optsOrCallback['status'],
        'membership_status': optsOrCallback['membershipStatus'],
        'account_id': optsOrCallback['accountId'],
        'organization_reserved_domain_id': optsOrCallback['organizationReservedDomainId'],
        'last_modified_since': optsOrCallback['lastModifiedSince']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = OrganizationUsersResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the updateEmailAddress operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~updateEmailAddressCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UsersUpdateResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Updates a user's email address.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {module:model/UpdateUsersEmailRequest} request The details about which email addresses to update
     * @param {module:api/UsersApi~updateEmailAddressCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UsersUpdateResponse}
     */
    this.updateEmailAddress = function(request, organizationId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling updateEmailAddress");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling updateEmailAddress");
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
      var returnType = UsersUpdateResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users/email_addresses', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the updateUser operation. If none specified a Promise will be returned.
     * @callback module:api/UsersApi~updateUserCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UsersUpdateResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Updates a user.
     * Required scopes: user_write
     * @param {String} organizationId The organization ID Guid
     * @param {module:model/UpdateUsersRequest} request The user details to update
     * @param {module:api/UsersApi~updateUserCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UsersUpdateResponse}
     */
    this.updateUser = function(request, organizationId, callback) {
      var postBody = request;

      // verify the required parameter 'organizationId' is set
      if (organizationId === undefined || organizationId === null) {
        throw new Error("Missing the required parameter 'organizationId' when calling updateUser");
      }

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling updateUser");
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
      var returnType = UsersUpdateResponse;

      return this.apiClient.callApi(
        '/v2/organizations/{organizationId}/users/profiles', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));