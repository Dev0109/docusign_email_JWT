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
    define(['ApiClient', 'model/OrgReportListResponseRequestor'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrgReportListResponseRequestor'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrgReportListResponseOrgReport = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrgReportListResponseRequestor);
  }
}(this, function(ApiClient, OrgReportListResponseRequestor) {
  'use strict';


  /**
   * The OrgReportListResponseOrgReport model module.
   * @module model/OrgReportListResponseOrgReport
   */

  /**
   * Constructs a new <code>OrgReportListResponseOrgReport</code>.
   * @alias module:model/OrgReportListResponseOrgReport
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrgReportListResponseOrgReport</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrgReportListResponseOrgReport} obj Optional instance to populate.
   * @return {module:model/OrgReportListResponseOrgReport} The populated <code>OrgReportListResponseOrgReport</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('complete')) {
        obj['complete'] = ApiClient.convertToType(data['complete'], 'Boolean');
      }
      if (data.hasOwnProperty('report_correlation_id')) {
        obj['report_correlation_id'] = ApiClient.convertToType(data['report_correlation_id'], 'String');
      }
      if (data.hasOwnProperty('site_id')) {
        obj['site_id'] = ApiClient.convertToType(data['site_id'], 'Number');
      }
      if (data.hasOwnProperty('report_id')) {
        obj['report_id'] = ApiClient.convertToType(data['report_id'], 'String');
      }
      if (data.hasOwnProperty('requestor')) {
        obj['requestor'] = OrgReportListResponseRequestor.constructFromObject(data['requestor']);
      }
      if (data.hasOwnProperty('created_on')) {
        obj['created_on'] = ApiClient.convertToType(data['created_on'], 'Date');
      }
      if (data.hasOwnProperty('account_export_count')) {
        obj['account_export_count'] = ApiClient.convertToType(data['account_export_count'], 'Number');
      }
      if (data.hasOwnProperty('url')) {
        obj['url'] = ApiClient.convertToType(data['url'], 'String');
      }
      if (data.hasOwnProperty('report_type_id')) {
        obj['report_type_id'] = ApiClient.convertToType(data['report_type_id'], 'String');
      }
      if (data.hasOwnProperty('report_date_range')) {
        obj['report_date_range'] = ApiClient.convertToType(data['report_date_range'], 'String');
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
   * @member {Boolean} complete
   */
  exports.prototype['complete'] = undefined;
  /**
   * @member {String} report_correlation_id
   */
  exports.prototype['report_correlation_id'] = undefined;
  /**
   * @member {Number} site_id
   */
  exports.prototype['site_id'] = undefined;
  /**
   * @member {String} report_id
   */
  exports.prototype['report_id'] = undefined;
  /**
   * @member {module:model/OrgReportListResponseRequestor} requestor
   */
  exports.prototype['requestor'] = undefined;
  /**
   * @member {Date} created_on
   */
  exports.prototype['created_on'] = undefined;
  /**
   * @member {Number} account_export_count
   */
  exports.prototype['account_export_count'] = undefined;
  /**
   * @member {String} url
   */
  exports.prototype['url'] = undefined;
  /**
   * @member {String} report_type_id
   */
  exports.prototype['report_type_id'] = undefined;
  /**
   * @member {String} report_date_range
   */
  exports.prototype['report_date_range'] = undefined;
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


