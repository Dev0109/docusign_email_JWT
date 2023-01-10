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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OASIRROrganizationAccountSettingsErrorDataResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OASIRROrganizationAccountSettingsErrorDataResponse model module.
   * @module model/OASIRROrganizationAccountSettingsErrorDataResponse
   */

  /**
   * Constructs a new <code>OASIRROrganizationAccountSettingsErrorDataResponse</code>.
   * @alias module:model/OASIRROrganizationAccountSettingsErrorDataResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OASIRROrganizationAccountSettingsErrorDataResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OASIRROrganizationAccountSettingsErrorDataResponse} obj Optional instance to populate.
   * @return {module:model/OASIRROrganizationAccountSettingsErrorDataResponse} The populated <code>OASIRROrganizationAccountSettingsErrorDataResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('account_name')) {
        obj['account_name'] = ApiClient.convertToType(data['account_name'], 'String');
      }
      if (data.hasOwnProperty('error')) {
        obj['error'] = ApiClient.convertToType(data['error'], 'String');
      }
      if (data.hasOwnProperty('error_key')) {
        obj['error_key'] = ApiClient.convertToType(data['error_key'], 'String');
      }
      if (data.hasOwnProperty('setting_key')) {
        obj['setting_key'] = ApiClient.convertToType(data['setting_key'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {String} account_name
   */
  exports.prototype['account_name'] = undefined;
  /**
   * @member {String} error
   */
  exports.prototype['error'] = undefined;
  /**
   * @member {String} error_key
   */
  exports.prototype['error_key'] = undefined;
  /**
   * @member {String} setting_key
   */
  exports.prototype['setting_key'] = undefined;



  return exports;
}));


