/**
 * DocuSign Click API
 * DocuSign Click lets you capture consent to standard agreement terms with a single click: terms and conditions, terms of service, terms of use, privacy policies, and more. The Click API lets you include this customizable clickwrap solution in your DocuSign integrations.
 *
 * OpenAPI spec version: v1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
	define(['Configuration', 'ApiClient', 'model/ClickwrapAgreementsResponse', 'model/ClickwrapRequest', 'model/ClickwrapTransferRequest', 'model/ClickwrapVersionDeleteResponse', 'model/ClickwrapVersionResponse', 'model/ClickwrapVersionSummaryResponse', 'model/ClickwrapVersionsDeleteResponse', 'model/ClickwrapVersionsPagedResponse', 'model/ClickwrapVersionsResponse', 'model/ClickwrapsDeleteResponse', 'model/Document', 'model/ErrorDetails', 'model/ServiceInformation', 'model/UserAgreementRequest', 'model/UserAgreementResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../Configuration'), require('../ApiClient'), require('../model/ClickwrapAgreementsResponse'), require('../model/ClickwrapRequest'), require('../model/ClickwrapTransferRequest'), require('../model/ClickwrapVersionDeleteResponse'), require('../model/ClickwrapVersionResponse'), require('../model/ClickwrapVersionSummaryResponse'), require('../model/ClickwrapVersionsDeleteResponse'), require('../model/ClickwrapVersionsPagedResponse'), require('../model/ClickwrapVersionsResponse'), require('../model/ClickwrapsDeleteResponse'), require('../model/Document'), require('../model/ErrorDetails'), require('../model/ServiceInformation'), require('../model/UserAgreementRequest'), require('../model/UserAgreementResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.AccountsApi = factory(root.DocusignClick.Configuration, root.DocusignClick.ApiClient, root.DocusignClick.ClickwrapAgreementsResponse, root.DocusignClick.ClickwrapRequest, root.DocusignClick.ClickwrapTransferRequest, root.DocusignClick.ClickwrapVersionDeleteResponse, root.DocusignClick.ClickwrapVersionResponse, root.DocusignClick.ClickwrapVersionSummaryResponse, root.DocusignClick.ClickwrapVersionsDeleteResponse, root.DocusignClick.ClickwrapVersionsPagedResponse, root.DocusignClick.ClickwrapVersionsResponse, root.DocusignClick.ClickwrapsDeleteResponse, root.DocusignClick.Document, root.DocusignClick.ErrorDetails, root.DocusignClick.ServiceInformation, root.DocusignClick.UserAgreementRequest, root.DocusignClick.UserAgreementResponse);
  }
}(this, function(Configuration, ApiClient, ClickwrapAgreementsResponse, ClickwrapRequest, ClickwrapTransferRequest, ClickwrapVersionDeleteResponse, ClickwrapVersionResponse, ClickwrapVersionSummaryResponse, ClickwrapVersionsDeleteResponse, ClickwrapVersionsPagedResponse, ClickwrapVersionsResponse, ClickwrapsDeleteResponse, Document, ErrorDetails, ServiceInformation, UserAgreementRequest, UserAgreementResponse) {
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
     * (Optional) Callback function to receive the result of the createClickwrap operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~createClickwrapCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionSummaryResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates a Clickwrap for the specified accountId
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/ClickwrapRequest} optsOrCallback.clickwrapRequest 
     * @param {module:api/AccountsApi~createClickwrapCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionSummaryResponse}
     */
    this.createClickwrap = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['clickwrapRequest'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createClickwrap");
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
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionSummaryResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createClickwrapVersion operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~createClickwrapVersionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionSummaryResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Creates the clickwrap version
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/ClickwrapRequest} optsOrCallback.clickwrapRequest 
     * @param {module:api/AccountsApi~createClickwrapVersionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionSummaryResponse}
     */
    this.createClickwrapVersion = function(accountId, clickwrapId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['clickwrapRequest'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createClickwrapVersion");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling createClickwrapVersion");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionSummaryResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the createHasAgreed operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~createHasAgreedCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UserAgreementResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Checks if a user has agreed to a clickwrap and returns a response with the agreement url. Returns HttpStatusCode.OK if user has no pending agreement.
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/UserAgreementRequest} optsOrCallback.userAgreementRequest 
     * @param {module:api/AccountsApi~createHasAgreedCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UserAgreementResponse}
     */
    this.createHasAgreed = function(accountId, clickwrapId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['userAgreementRequest'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling createHasAgreed");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling createHasAgreed");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = UserAgreementResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/agreements', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteClickwrap operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~deleteClickwrapCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionsDeleteResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes the clickwrap and all its version specified by clickwrapId. Active clickwrap will not get deleted
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.versions 
     * @param {module:api/AccountsApi~deleteClickwrapCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionsDeleteResponse}
     */
    this.deleteClickwrap = function(accountId, clickwrapId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteClickwrap");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling deleteClickwrap");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
        'versions': optsOrCallback['versions']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionsDeleteResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteClickwrapVersion operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~deleteClickwrapVersionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionDeleteResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Delete a Clickwrap version specified by versionId
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} versionId 
     * @param {module:api/AccountsApi~deleteClickwrapVersionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionDeleteResponse}
     */
    this.deleteClickwrapVersion = function(accountId, clickwrapId, versionId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteClickwrapVersion");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling deleteClickwrapVersion");
      }

      // verify the required parameter 'versionId' is set
      if (versionId === undefined || versionId === null) {
        throw new Error("Missing the required parameter 'versionId' when calling deleteClickwrapVersion");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'versionId': versionId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionDeleteResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions/{versionId}', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteClickwrapVersions operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~deleteClickwrapVersionsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionsDeleteResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes the versions specified by query parameter clickwrapVersionIds for a clickwrap, or all versions if no query parameter is specified. It will not delete if a version is active.
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.clickwrapVersionIds 
     * @param {module:api/AccountsApi~deleteClickwrapVersionsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionsDeleteResponse}
     */
    this.deleteClickwrapVersions = function(accountId, clickwrapId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteClickwrapVersions");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling deleteClickwrapVersions");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
        'clickwrapVersionIds': optsOrCallback['clickwrapVersionIds']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionsDeleteResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the deleteClickwraps operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~deleteClickwrapsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapsDeleteResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Deletes all the clickwraps for an account or the ones passed in query parameter clickwrapIds. It will not delete active clickwraps.
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.clickwrapIds 
     * @param {module:api/AccountsApi~deleteClickwrapsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapsDeleteResponse}
     */
    this.deleteClickwraps = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling deleteClickwraps");
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
        'clickwrapIds': optsOrCallback['clickwrapIds']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapsDeleteResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps', 'DELETE',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getAgreement operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getAgreementCallback
     * @param {String} error Error message, if any.
     * @param {module:model/UserAgreementResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets the agreement by a provided agreement ID
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} agreementId 
     * @param {module:api/AccountsApi~getAgreementCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/UserAgreementResponse}
     */
    this.getAgreement = function(accountId, clickwrapId, agreementId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getAgreement");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getAgreement");
      }

      // verify the required parameter 'agreementId' is set
      if (agreementId === undefined || agreementId === null) {
        throw new Error("Missing the required parameter 'agreementId' when calling getAgreement");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'agreementId': agreementId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = UserAgreementResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/agreements/{agreementId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getAgreementDocument operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getAgreementDocumentCallback
     * @param {String} error Error message, if any.
     * @param {module:model/Document} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Downloads a document at an order within the agreement.
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} versionId 
     * @param {String} orderOrDisclosure 
     * @param {module:api/AccountsApi~getAgreementDocumentCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/Document}
     */
    this.getAgreementDocument = function(accountId, clickwrapId, versionId, orderOrDisclosure, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getAgreementDocument");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getAgreementDocument");
      }

      // verify the required parameter 'versionId' is set
      if (versionId === undefined || versionId === null) {
        throw new Error("Missing the required parameter 'versionId' when calling getAgreementDocument");
      }

      // verify the required parameter 'orderOrDisclosure' is set
      if (orderOrDisclosure === undefined || orderOrDisclosure === null) {
        throw new Error("Missing the required parameter 'orderOrDisclosure' when calling getAgreementDocument");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'versionId': versionId,
        'orderOrDisclosure': orderOrDisclosure
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = Document;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions/{versionId}/documents/{orderOrDisclosure}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getAgreementPdf operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getAgreementPdfCallback
     * @param {String} error Error message, if any.
     * @param {Object} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Downloads the agreement PDF and optionally certificate of completion.
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} agreementId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.includeCoc 
     * @param {module:api/AccountsApi~getAgreementPdfCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link Object}
     */
    this.getAgreementPdf = function(accountId, clickwrapId, agreementId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getAgreementPdf");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getAgreementPdf");
      }

      // verify the required parameter 'agreementId' is set
      if (agreementId === undefined || agreementId === null) {
        throw new Error("Missing the required parameter 'agreementId' when calling getAgreementPdf");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'agreementId': agreementId
      };
      var queryParams = {
        'include_coc': optsOrCallback['includeCoc']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/pdf'];
      var returnType = Object;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/agreements/{agreementId}/download', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getClickwrap operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getClickwrapCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets the clickwrap for an account specified by clickwrapId
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {module:api/AccountsApi~getClickwrapCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionResponse}
     */
    this.getClickwrap = function(accountId, clickwrapId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getClickwrap");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getClickwrap");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getClickwrapAgreements operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getClickwrapAgreementsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapAgreementsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets the agreement responses for a clickwrap
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.clientUserId 
     * @param {String} optsOrCallback.fromDate 
     * @param {String} optsOrCallback.pageNumber 
     * @param {String} optsOrCallback.status 
     * @param {String} optsOrCallback.toDate 
     * @param {module:api/AccountsApi~getClickwrapAgreementsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapAgreementsResponse}
     */
    this.getClickwrapAgreements = function(accountId, clickwrapId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getClickwrapAgreements");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getClickwrapAgreements");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
        'client_user_id': optsOrCallback['clientUserId'],
        'from_date': optsOrCallback['fromDate'],
        'page_number': optsOrCallback['pageNumber'],
        'status': optsOrCallback['status'],
        'to_date': optsOrCallback['toDate']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapAgreementsResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/users', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getClickwrapVersion operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getClickwrapVersionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets the Clickwrap version by clickwrapId and versionId for an account
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} versionId 
     * @param {module:api/AccountsApi~getClickwrapVersionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionResponse}
     */
    this.getClickwrapVersion = function(accountId, clickwrapId, versionId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getClickwrapVersion");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getClickwrapVersion");
      }

      // verify the required parameter 'versionId' is set
      if (versionId === undefined || versionId === null) {
        throw new Error("Missing the required parameter 'versionId' when calling getClickwrapVersion");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'versionId': versionId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions/{versionId}', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getClickwrapVersionAgreements operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getClickwrapVersionAgreementsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapAgreementsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets the agreement responses for a clickwrap version
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} versionId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.clientUserId 
     * @param {String} optsOrCallback.fromDate 
     * @param {String} optsOrCallback.pageNumber 
     * @param {String} optsOrCallback.status 
     * @param {String} optsOrCallback.toDate 
     * @param {module:api/AccountsApi~getClickwrapVersionAgreementsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapAgreementsResponse}
     */
    this.getClickwrapVersionAgreements = function(accountId, clickwrapId, versionId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getClickwrapVersionAgreements");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getClickwrapVersionAgreements");
      }

      // verify the required parameter 'versionId' is set
      if (versionId === undefined || versionId === null) {
        throw new Error("Missing the required parameter 'versionId' when calling getClickwrapVersionAgreements");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'versionId': versionId
      };
      var queryParams = {
        'client_user_id': optsOrCallback['clientUserId'],
        'from_date': optsOrCallback['fromDate'],
        'page_number': optsOrCallback['pageNumber'],
        'status': optsOrCallback['status'],
        'to_date': optsOrCallback['toDate']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapAgreementsResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions/{versionId}/users', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getClickwrapVersions operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getClickwrapVersionsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionsPagedResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets all the versions of a clickwrap for an account
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {module:api/AccountsApi~getClickwrapVersionsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionsPagedResponse}
     */
    this.getClickwrapVersions = function(accountId, clickwrapId, callback) {
      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getClickwrapVersions");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling getClickwrapVersions");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionsPagedResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getClickwraps operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getClickwrapsCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionsResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Gets the Clickwraps for an account
     * @param {String} accountId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {String} optsOrCallback.filter 
     * @param {String} optsOrCallback.fromDate 
     * @param {String} optsOrCallback.name 
     * @param {String} optsOrCallback.ownerUserId 
     * @param {String} optsOrCallback.pageNumber 
     * @param {String} optsOrCallback.status 
     * @param {String} optsOrCallback.toDate 
     * @param {module:api/AccountsApi~getClickwrapsCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionsResponse}
     */
    this.getClickwraps = function(accountId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = null;

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling getClickwraps");
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
        'filter': optsOrCallback['filter'],
        'from_date': optsOrCallback['fromDate'],
        'name': optsOrCallback['name'],
        'ownerUserId': optsOrCallback['ownerUserId'],
        'page_number': optsOrCallback['pageNumber'],
        'status': optsOrCallback['status'],
        'to_date': optsOrCallback['toDate']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionsResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the getServiceInformation operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~getServiceInformationCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ServiceInformation} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Provides base service and version access information.
     * @param {module:api/AccountsApi~getServiceInformationCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ServiceInformation}
     */
    this.getServiceInformation = function(callback) {
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
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ServiceInformation;

      return this.apiClient.callApi(
        '/service_information', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the updateClickwrap operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~updateClickwrapCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionSummaryResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Updates the clickwrap specified by clickwrapId
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/ClickwrapTransferRequest} optsOrCallback.clickwrapTransferRequest 
     * @param {module:api/AccountsApi~updateClickwrapCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionSummaryResponse}
     */
    this.updateClickwrap = function(accountId, clickwrapId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['clickwrapTransferRequest'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling updateClickwrap");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling updateClickwrap");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionSummaryResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}', 'PUT',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };

    /**
     * (Optional) Callback function to receive the result of the updateClickwrapVersion operation. If none specified a Promise will be returned.
     * @callback module:api/AccountsApi~updateClickwrapVersionCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ClickwrapVersionSummaryResponse} data The data returned by the service call.
     * @param {String} If a callback was specified, the response The complete HTTP response, else a Promise resolving the response Data.
     */

    /**
     * Updates the clickwrap version specified by versionId
     * @param {String} accountId 
     * @param {String} clickwrapId 
     * @param {String} versionId 
     * @param {Object} optsOrCallback Optional parameters, if you are passing no optional parameters, you can either pass a null or omit this parameter entirely.
     * @param {module:model/ClickwrapRequest} optsOrCallback.clickwrapRequest 
     * @param {module:api/AccountsApi~updateClickwrapVersionCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {@link module:model/ClickwrapVersionSummaryResponse}
     */
    this.updateClickwrapVersion = function(accountId, clickwrapId, versionId, optsOrCallback, callback) {
      optsOrCallback = optsOrCallback || {};

      if (typeof optsOrCallback === 'function') {
        callback = optsOrCallback;
        optsOrCallback = {};
      }

      var postBody = optsOrCallback['clickwrapRequest'];

      // verify the required parameter 'accountId' is set
      if (accountId === undefined || accountId === null) {
        throw new Error("Missing the required parameter 'accountId' when calling updateClickwrapVersion");
      }

      // verify the required parameter 'clickwrapId' is set
      if (clickwrapId === undefined || clickwrapId === null) {
        throw new Error("Missing the required parameter 'clickwrapId' when calling updateClickwrapVersion");
      }

      // verify the required parameter 'versionId' is set
      if (versionId === undefined || versionId === null) {
        throw new Error("Missing the required parameter 'versionId' when calling updateClickwrapVersion");
      }

      if (typeof callback !== 'function' &&  arguments.length && typeof arguments[arguments.length-1] === 'function'){
        if (typeof optsOrCallback !== 'undefined') {
          optsOrCallback = callback;
        }
        callback = arguments[arguments.length-1];
      }

      var pathParams = {
        'accountId': accountId,
        'clickwrapId': clickwrapId,
        'versionId': versionId
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = ['docusignAccessCode'];
      var contentTypes = [];
      var accepts = ['application/json'];
      var returnType = ClickwrapVersionSummaryResponse;

      return this.apiClient.callApi(
        '/v1/accounts/{accountId}/clickwraps/{clickwrapId}/versions/{versionId}', 'PUT',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType, callback
      );
    };
  };

  return exports;
}));