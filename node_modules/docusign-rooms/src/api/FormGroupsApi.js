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
	define(['Configuration', 'ApiClient', 'model/ApiError', 'model/FormGroup', 'model/FormGroupForCreate', 'model/FormGroupForUpdate', 'model/FormGroupFormToAssign', 'model/FormGroupSummaryList'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ApiError'), require('../model/FormGroup'), require('../model/FormGroupForCreate'), require('../model/FormGroupForUpdate'), require('../model/FormGroupFormToAssign'), require('../model/FormGroupSummaryList'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.FormGroupsApi = factory(root.DocusignRooms.Configuration, root.DocusignRooms.ApiClient, root.DocusignRooms.ApiError, root.DocusignRooms.FormGroup, root.DocusignRooms.FormGroupForCreate, root.DocusignRooms.FormGroupForUpdate, root.DocusignRooms.FormGroupFormToAssign, root.DocusignRooms.FormGroupSummaryList);
  }
}(this, function(Configuration, ApiClient, ApiError, FormGroup, FormGroupForCreate, FormGroupForUpdate, FormGroupFormToAssign, FormGroupSummaryList) {
  'use strict';

  /**
   * FormGroups service.
   * @module api/FormGroupsApi
   */

  /**
   * Constructs a new FormGroupsApi. 
   * @alias module:api/FormGroupsApi
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
     * (Optional) Callback function to receive the result of the assignFormGroupForm operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~assignFormGroupFormCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormGroupFormToAssign} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Assigns a form to a form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/FormGroupFormToAssign} optsOrCallback.body 
     * @param {module:api/FormGroupsApi~assignFormGroupFormCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormGroupFormToAssign}
     */
    this.assignFormGroupForm = function(accountId, formGroupId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling assignFormGroupForm");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling assignFormGroupForm");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId
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
      var returnType = FormGroupFormToAssign;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_groups/{formGroupId}/assign_form', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createFormGroup operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~createFormGroupCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormGroup} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a form group.
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/FormGroupForCreate} optsOrCallback.body 
     * @param {module:api/FormGroupsApi~createFormGroupCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormGroup}
     */
    this.createFormGroup = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createFormGroup");
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
      var returnType = FormGroup;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_groups', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteFormGroup operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~deleteFormGroupCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes a form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {module:api/FormGroupsApi~deleteFormGroupCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.deleteFormGroup = function(accountId, formGroupId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteFormGroup");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling deleteFormGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId
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
        '/v2/accounts/{accountId}/form_groups/{formGroupId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getFormGroup operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~getFormGroupCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormGroup} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets a form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {module:api/FormGroupsApi~getFormGroupCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormGroup}
     */
    this.getFormGroup = function(accountId, formGroupId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getFormGroup");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling getFormGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId
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
      var returnType = FormGroup;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_groups/{formGroupId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getFormGroups operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~getFormGroupsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormGroupSummaryList} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Get account Form Groups.
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {Number} optsOrCallback.count Number of Form Groups to include in the response, (Default 100). (default to 100)
     * @param {Number} optsOrCallback.startPosition Position in the overall list of Form Groups to begin results. (default to 0)
     * @param {module:api/FormGroupsApi~getFormGroupsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormGroupSummaryList}
     */
    this.getFormGroups = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getFormGroups");
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
        'startPosition': optsOrCallback['startPosition']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['text/plain', 'application/json', 'text/json'];
      var returnType = FormGroupSummaryList;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_groups', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the grantOfficeAccessToFormGroup operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~grantOfficeAccessToFormGroupCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Assign office to a form group so the specified office has access to the form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {Number} officeId 
     * @param {module:api/FormGroupsApi~grantOfficeAccessToFormGroupCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.grantOfficeAccessToFormGroup = function(accountId, formGroupId, officeId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling grantOfficeAccessToFormGroup");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling grantOfficeAccessToFormGroup");
      }

      // verify the required parameter 'officeId' is set
      if (officeId === undefined || officeId === null) {
        throw new Error("Missing the required parameter 'officeId' when calling grantOfficeAccessToFormGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId,
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
        '/v2/accounts/{accountId}/form_groups/{formGroupId}/grant_office_access/{officeId}', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the removeFormGroupForm operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~removeFormGroupFormCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Removes a form from a form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {String} formId 
     * @param {module:api/FormGroupsApi~removeFormGroupFormCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.removeFormGroupForm = function(accountId, formGroupId, formId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling removeFormGroupForm");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling removeFormGroupForm");
      }

      // verify the required parameter 'formId' is set
      if (formId === undefined || formId === null) {
        throw new Error("Missing the required parameter 'formId' when calling removeFormGroupForm");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId,
        'formId': formId
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
        '/v2/accounts/{accountId}/form_groups/{formGroupId}/unassign_form/{formId}', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the renameFormGroup operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~renameFormGroupCallback
     * @param {String} error Error message, if any.
     * @param {module:model/FormGroup} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Renames a form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/FormGroupForUpdate} optsOrCallback.body 
     * @param {module:api/FormGroupsApi~renameFormGroupCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/FormGroup}
     */
    this.renameFormGroup = function(accountId, formGroupId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['body'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling renameFormGroup");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling renameFormGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId
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
      var returnType = FormGroup;

      return this.apiClient.callApi(
        '/v2/accounts/{accountId}/form_groups/{formGroupId}', 'PUT',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the revokeOfficeAccessFromFormGroup operation. If none specified a Promise will be returned.
     * @callback module:api/FormGroupsApi~revokeOfficeAccessFromFormGroupCallback
     * @param {String} error Error message, if any.
     * @param data This operation does not return a value.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Remove office to a form group so the specified office doesn't have access to the form group.
     * @param {String} accountId 
     * @param {String} formGroupId 
     * @param {Number} officeId 
     * @param {module:api/FormGroupsApi~revokeOfficeAccessFromFormGroupCallback} callback The callback function, accepting three arguments: error, data, response
     */
    this.revokeOfficeAccessFromFormGroup = function(accountId, formGroupId, officeId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling revokeOfficeAccessFromFormGroup");
      }

      // verify the required parameter 'formGroupId' is set
      if (formGroupId === undefined || formGroupId === null) {
        throw new Error("Missing the required parameter 'formGroupId' when calling revokeOfficeAccessFromFormGroup");
      }

      // verify the required parameter 'officeId' is set
      if (officeId === undefined || officeId === null) {
        throw new Error("Missing the required parameter 'officeId' when calling revokeOfficeAccessFromFormGroup");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'formGroupId': formGroupId,
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
        '/v2/accounts/{accountId}/form_groups/{formGroupId}/revoke_office_access/{officeId}', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));