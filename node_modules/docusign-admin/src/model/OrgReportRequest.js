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
    root.DocusignAdmin.OrgReportRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrgReportRequest model module.
   * @module model/OrgReportRequest
   */

  /**
   * Constructs a new <code>OrgReportRequest</code>.
   * @alias module:model/OrgReportRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrgReportRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrgReportRequest} obj Optional instance to populate.
   * @return {module:model/OrgReportRequest} The populated <code>OrgReportRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('report_type')) {
        obj['report_type'] = ApiClient.convertToType(data['report_type'], 'String');
      }
      if (data.hasOwnProperty('report_date_range')) {
        obj['report_date_range'] = ApiClient.convertToType(data['report_date_range'], 'String');
      }
      if (data.hasOwnProperty('account_ids')) {
        obj['account_ids'] = ApiClient.convertToType(data['account_ids'], ['String']);
      }
      if (data.hasOwnProperty('custom_start_date')) {
        obj['custom_start_date'] = ApiClient.convertToType(data['custom_start_date'], 'Date');
      }
      if (data.hasOwnProperty('custom_end_date')) {
        obj['custom_end_date'] = ApiClient.convertToType(data['custom_end_date'], 'Date');
      }
    }
    return obj;
  }

  /**
   * @member {String} report_type
   */
  exports.prototype['report_type'] = undefined;
  /**
   * @member {String} report_date_range
   */
  exports.prototype['report_date_range'] = undefined;
  /**
   * @member {Array.<String>} account_ids
   */
  exports.prototype['account_ids'] = undefined;
  /**
   * @member {Date} custom_start_date
   */
  exports.prototype['custom_start_date'] = undefined;
  /**
   * @member {Date} custom_end_date
   */
  exports.prototype['custom_end_date'] = undefined;



  return exports;
}));


