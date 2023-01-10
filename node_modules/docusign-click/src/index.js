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
(function(factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['Configuration', 'ApiClient', 'model/ClickwrapAgreementsResponse', 'model/ClickwrapDeleteResponse', 'model/ClickwrapRequest', 'model/ClickwrapScheduledReacceptance', 'model/ClickwrapTransferRequest', 'model/ClickwrapVersion', 'model/ClickwrapVersionDeleteResponse', 'model/ClickwrapVersionResponse', 'model/ClickwrapVersionSummaryResponse', 'model/ClickwrapVersionsDeleteResponse', 'model/ClickwrapVersionsPagedResponse', 'model/ClickwrapVersionsResponse', 'model/ClickwrapsDeleteResponse', 'model/DataField', 'model/DisplaySettings', 'model/Document', 'model/ErrorDetails', 'model/ServiceInformation', 'model/ServiceVersion', 'model/UserAgreementRequest', 'model/UserAgreementResponse', 'api/AccountsApi'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('./Configuration'), require('./ApiClient'), require('./model/ClickwrapAgreementsResponse'), require('./model/ClickwrapDeleteResponse'), require('./model/ClickwrapRequest'), require('./model/ClickwrapScheduledReacceptance'), require('./model/ClickwrapTransferRequest'), require('./model/ClickwrapVersion'), require('./model/ClickwrapVersionDeleteResponse'), require('./model/ClickwrapVersionResponse'), require('./model/ClickwrapVersionSummaryResponse'), require('./model/ClickwrapVersionsDeleteResponse'), require('./model/ClickwrapVersionsPagedResponse'), require('./model/ClickwrapVersionsResponse'), require('./model/ClickwrapsDeleteResponse'), require('./model/DataField'), require('./model/DisplaySettings'), require('./model/Document'), require('./model/ErrorDetails'), require('./model/ServiceInformation'), require('./model/ServiceVersion'), require('./model/UserAgreementRequest'), require('./model/UserAgreementResponse'), require('./api/AccountsApi'));
  }
}(function(Configuration, ApiClient, ClickwrapAgreementsResponse, ClickwrapDeleteResponse, ClickwrapRequest, ClickwrapScheduledReacceptance, ClickwrapTransferRequest, ClickwrapVersion, ClickwrapVersionDeleteResponse, ClickwrapVersionResponse, ClickwrapVersionSummaryResponse, ClickwrapVersionsDeleteResponse, ClickwrapVersionsPagedResponse, ClickwrapVersionsResponse, ClickwrapsDeleteResponse, DataField, DisplaySettings, Document, ErrorDetails, ServiceInformation, ServiceVersion, UserAgreementRequest, UserAgreementResponse, AccountsApi) {
  'use strict';

  /**
   * DocuSign Node.js API client..<br>
   * The <code>index</code> module provides access to constructors for all the classes which comprise the public API.
   * <p>
   * An AMD (recommended!) or CommonJS application will generally do something equivalent to the following:
   * <pre>
   * var DocusignClick = require('index'); // See note below*.
   * var xxxSvc = new DocusignClick.XxxApi(); // Allocate the API class we're going to use.
   * var yyyModel = new DocusignClick.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * <em>*NOTE: For a top-level AMD script, use require(['index'], function(){...})
   * and put the application logic within the callback function.</em>
   * </p>
   * <p>
   * A non-AMD browser application (discouraged) might do something like this:
   * <pre>
   * var xxxSvc = new DocusignClick.XxxApi(); // Allocate the API class we're going to use.
   * var yyy = new DocusignClick.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * </p>
   * @module index
   */
  var exports = {
	/**
	 * The configuration constructor.
	 * @property {module:Configuration}
	 */
	 Configuration: Configuration,
	/**
     * The ApiClient constructor.
     * @property {module:ApiClient}
     */
    ApiClient: ApiClient,
    /**
     * The ClickwrapAgreementsResponse model constructor.
     * @property {module:model/ClickwrapAgreementsResponse}
     */
    ClickwrapAgreementsResponse: ClickwrapAgreementsResponse,
    /**
     * The ClickwrapDeleteResponse model constructor.
     * @property {module:model/ClickwrapDeleteResponse}
     */
    ClickwrapDeleteResponse: ClickwrapDeleteResponse,
    /**
     * The ClickwrapRequest model constructor.
     * @property {module:model/ClickwrapRequest}
     */
    ClickwrapRequest: ClickwrapRequest,
    /**
     * The ClickwrapScheduledReacceptance model constructor.
     * @property {module:model/ClickwrapScheduledReacceptance}
     */
    ClickwrapScheduledReacceptance: ClickwrapScheduledReacceptance,
    /**
     * The ClickwrapTransferRequest model constructor.
     * @property {module:model/ClickwrapTransferRequest}
     */
    ClickwrapTransferRequest: ClickwrapTransferRequest,
    /**
     * The ClickwrapVersion model constructor.
     * @property {module:model/ClickwrapVersion}
     */
    ClickwrapVersion: ClickwrapVersion,
    /**
     * The ClickwrapVersionDeleteResponse model constructor.
     * @property {module:model/ClickwrapVersionDeleteResponse}
     */
    ClickwrapVersionDeleteResponse: ClickwrapVersionDeleteResponse,
    /**
     * The ClickwrapVersionResponse model constructor.
     * @property {module:model/ClickwrapVersionResponse}
     */
    ClickwrapVersionResponse: ClickwrapVersionResponse,
    /**
     * The ClickwrapVersionSummaryResponse model constructor.
     * @property {module:model/ClickwrapVersionSummaryResponse}
     */
    ClickwrapVersionSummaryResponse: ClickwrapVersionSummaryResponse,
    /**
     * The ClickwrapVersionsDeleteResponse model constructor.
     * @property {module:model/ClickwrapVersionsDeleteResponse}
     */
    ClickwrapVersionsDeleteResponse: ClickwrapVersionsDeleteResponse,
    /**
     * The ClickwrapVersionsPagedResponse model constructor.
     * @property {module:model/ClickwrapVersionsPagedResponse}
     */
    ClickwrapVersionsPagedResponse: ClickwrapVersionsPagedResponse,
    /**
     * The ClickwrapVersionsResponse model constructor.
     * @property {module:model/ClickwrapVersionsResponse}
     */
    ClickwrapVersionsResponse: ClickwrapVersionsResponse,
    /**
     * The ClickwrapsDeleteResponse model constructor.
     * @property {module:model/ClickwrapsDeleteResponse}
     */
    ClickwrapsDeleteResponse: ClickwrapsDeleteResponse,
    /**
     * The DataField model constructor.
     * @property {module:model/DataField}
     */
    DataField: DataField,
    /**
     * The DisplaySettings model constructor.
     * @property {module:model/DisplaySettings}
     */
    DisplaySettings: DisplaySettings,
    /**
     * The Document model constructor.
     * @property {module:model/Document}
     */
    Document: Document,
    /**
     * The ErrorDetails model constructor.
     * @property {module:model/ErrorDetails}
     */
    ErrorDetails: ErrorDetails,
    /**
     * The ServiceInformation model constructor.
     * @property {module:model/ServiceInformation}
     */
    ServiceInformation: ServiceInformation,
    /**
     * The ServiceVersion model constructor.
     * @property {module:model/ServiceVersion}
     */
    ServiceVersion: ServiceVersion,
    /**
     * The UserAgreementRequest model constructor.
     * @property {module:model/UserAgreementRequest}
     */
    UserAgreementRequest: UserAgreementRequest,
    /**
     * The UserAgreementResponse model constructor.
     * @property {module:model/UserAgreementResponse}
     */
    UserAgreementResponse: UserAgreementResponse,
    /**
     * The AccountsApi service constructor.
     * @property {module:api/AccountsApi}
     */
    AccountsApi: AccountsApi
  };

  return exports;
}));