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
    define(['ApiClient', 'model/OrganizationAccountSettingsImportRequestorResponse', 'model/OrganizationAccountSettingsImportResultResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationAccountSettingsImportRequestorResponse'), require('./OrganizationAccountSettingsImportResultResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationAccountSettingsImportResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationAccountSettingsImportRequestorResponse, root.DocusignAdmin.OrganizationAccountSettingsImportResultResponse);
  }
}(this, function(ApiClient, OrganizationAccountSettingsImportRequestorResponse, OrganizationAccountSettingsImportResultResponse) {
  'use strict';


  /**
   * The OrganizationAccountSettingsImportResponse model module.
   * @module model/OrganizationAccountSettingsImportResponse
   */

  /**
   * Constructs a new <code>OrganizationAccountSettingsImportResponse</code>.
   * @alias module:model/OrganizationAccountSettingsImportResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationAccountSettingsImportResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationAccountSettingsImportResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationAccountSettingsImportResponse} The populated <code>OrganizationAccountSettingsImportResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('created')) {
        obj['created'] = ApiClient.convertToType(data['created'], 'Date');
      }
      if (data.hasOwnProperty('last_modified')) {
        obj['last_modified'] = ApiClient.convertToType(data['last_modified'], 'Date');
      }
      if (data.hasOwnProperty('completed')) {
        obj['completed'] = ApiClient.convertToType(data['completed'], 'Date');
      }
      if (data.hasOwnProperty('expires')) {
        obj['expires'] = ApiClient.convertToType(data['expires'], 'Date');
      }
      if (data.hasOwnProperty('percent_completed')) {
        obj['percent_completed'] = ApiClient.convertToType(data['percent_completed'], 'Number');
      }
      if (data.hasOwnProperty('number_processed_accounts')) {
        obj['number_processed_accounts'] = ApiClient.convertToType(data['number_processed_accounts'], 'Number');
      }
      if (data.hasOwnProperty('number_unprocessed_accounts')) {
        obj['number_unprocessed_accounts'] = ApiClient.convertToType(data['number_unprocessed_accounts'], 'Number');
      }
      if (data.hasOwnProperty('results')) {
        obj['results'] = ApiClient.convertToType(data['results'], [OrganizationAccountSettingsImportResultResponse]);
      }
      if (data.hasOwnProperty('success')) {
        obj['success'] = ApiClient.convertToType(data['success'], 'Boolean');
      }
      if (data.hasOwnProperty('skipped_settings_by_account')) {
        obj['skipped_settings_by_account'] = ApiClient.convertToType(data['skipped_settings_by_account'], {'String': ['String']});
      }
      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('organization_id')) {
        obj['organization_id'] = ApiClient.convertToType(data['organization_id'], 'String');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('requestor')) {
        obj['requestor'] = OrganizationAccountSettingsImportRequestorResponse.constructFromObject(data['requestor']);
      }
    }
    return obj;
  }

  /**
   * @member {Date} created
   */
  exports.prototype['created'] = undefined;
  /**
   * @member {Date} last_modified
   */
  exports.prototype['last_modified'] = undefined;
  /**
   * @member {Date} completed
   */
  exports.prototype['completed'] = undefined;
  /**
   * @member {Date} expires
   */
  exports.prototype['expires'] = undefined;
  /**
   * @member {Number} percent_completed
   */
  exports.prototype['percent_completed'] = undefined;
  /**
   * @member {Number} number_processed_accounts
   */
  exports.prototype['number_processed_accounts'] = undefined;
  /**
   * @member {Number} number_unprocessed_accounts
   */
  exports.prototype['number_unprocessed_accounts'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationAccountSettingsImportResultResponse>} results
   */
  exports.prototype['results'] = undefined;
  /**
   * @member {Boolean} success
   */
  exports.prototype['success'] = undefined;
  /**
   * @member {Object.<String, Array.<String>>} skipped_settings_by_account
   */
  exports.prototype['skipped_settings_by_account'] = undefined;
  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} organization_id
   */
  exports.prototype['organization_id'] = undefined;
  /**
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * @member {String} type
   */
  exports.prototype['type'] = undefined;
  /**
   * @member {module:model/OrganizationAccountSettingsImportRequestorResponse} requestor
   */
  exports.prototype['requestor'] = undefined;



  return exports;
}));


