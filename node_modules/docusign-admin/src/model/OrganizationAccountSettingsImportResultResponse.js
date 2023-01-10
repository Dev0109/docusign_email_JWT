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
    define(['ApiClient', 'model/OASIRRErrorDetails', 'model/OASIRROrganizationAccountSettingsErrorDataResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OASIRRErrorDetails'), require('./OASIRROrganizationAccountSettingsErrorDataResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationAccountSettingsImportResultResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OASIRRErrorDetails, root.DocusignAdmin.OASIRROrganizationAccountSettingsErrorDataResponse);
  }
}(this, function(ApiClient, OASIRRErrorDetails, OASIRROrganizationAccountSettingsErrorDataResponse) {
  'use strict';


  /**
   * The OrganizationAccountSettingsImportResultResponse model module.
   * @module model/OrganizationAccountSettingsImportResultResponse
   */

  /**
   * Constructs a new <code>OrganizationAccountSettingsImportResultResponse</code>.
   * @alias module:model/OrganizationAccountSettingsImportResultResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationAccountSettingsImportResultResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationAccountSettingsImportResultResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationAccountSettingsImportResultResponse} The populated <code>OrganizationAccountSettingsImportResultResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('site_id')) {
        obj['site_id'] = ApiClient.convertToType(data['site_id'], 'Number');
      }
      if (data.hasOwnProperty('url')) {
        obj['url'] = ApiClient.convertToType(data['url'], 'String');
      }
      if (data.hasOwnProperty('number_processed_accounts')) {
        obj['number_processed_accounts'] = ApiClient.convertToType(data['number_processed_accounts'], 'Number');
      }
      if (data.hasOwnProperty('error_details')) {
        obj['error_details'] = OASIRRErrorDetails.constructFromObject(data['error_details']);
      }
      if (data.hasOwnProperty('processing_issues_by_account')) {
        obj['processing_issues_by_account'] = ApiClient.convertToType(data['processing_issues_by_account'], [OASIRROrganizationAccountSettingsErrorDataResponse]);
      }
      if (data.hasOwnProperty('number_unprocessed_accounts')) {
        obj['number_unprocessed_accounts'] = ApiClient.convertToType(data['number_unprocessed_accounts'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {Number} site_id
   */
  exports.prototype['site_id'] = undefined;
  /**
   * @member {String} url
   */
  exports.prototype['url'] = undefined;
  /**
   * @member {Number} number_processed_accounts
   */
  exports.prototype['number_processed_accounts'] = undefined;
  /**
   * @member {module:model/OASIRRErrorDetails} error_details
   */
  exports.prototype['error_details'] = undefined;
  /**
   * @member {Array.<module:model/OASIRROrganizationAccountSettingsErrorDataResponse>} processing_issues_by_account
   */
  exports.prototype['processing_issues_by_account'] = undefined;
  /**
   * @member {Number} number_unprocessed_accounts
   */
  exports.prototype['number_unprocessed_accounts'] = undefined;



  return exports;
}));


