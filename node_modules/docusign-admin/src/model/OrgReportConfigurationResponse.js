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
    root.DocusignAdmin.OrgReportConfigurationResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrgReportConfigurationResponse model module.
   * @module model/OrgReportConfigurationResponse
   */

  /**
   * Constructs a new <code>OrgReportConfigurationResponse</code>.
   * @alias module:model/OrgReportConfigurationResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrgReportConfigurationResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrgReportConfigurationResponse} obj Optional instance to populate.
   * @return {module:model/OrgReportConfigurationResponse} The populated <code>OrgReportConfigurationResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('is_account_limit_disabled')) {
        obj['is_account_limit_disabled'] = ApiClient.convertToType(data['is_account_limit_disabled'], 'Boolean');
      }
      if (data.hasOwnProperty('custom_dates_enabled')) {
        obj['custom_dates_enabled'] = ApiClient.convertToType(data['custom_dates_enabled'], 'Boolean');
      }
      if (data.hasOwnProperty('enabled_report_types')) {
        obj['enabled_report_types'] = ApiClient.convertToType(data['enabled_report_types'], ['Number']);
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} is_account_limit_disabled
   */
  exports.prototype['is_account_limit_disabled'] = undefined;
  /**
   * @member {Boolean} custom_dates_enabled
   */
  exports.prototype['custom_dates_enabled'] = undefined;
  /**
   * @member {Array.<Number>} enabled_report_types
   */
  exports.prototype['enabled_report_types'] = undefined;



  return exports;
}));


