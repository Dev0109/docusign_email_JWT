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
    root.DocusignAdmin.OrgReportCreateResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrgReportCreateResponse model module.
   * @module model/OrgReportCreateResponse
   */

  /**
   * Constructs a new <code>OrgReportCreateResponse</code>.
   * @alias module:model/OrgReportCreateResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrgReportCreateResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrgReportCreateResponse} obj Optional instance to populate.
   * @return {module:model/OrgReportCreateResponse} The populated <code>OrgReportCreateResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('report_correlation_id')) {
        obj['report_correlation_id'] = ApiClient.convertToType(data['report_correlation_id'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} report_correlation_id
   */
  exports.prototype['report_correlation_id'] = undefined;



  return exports;
}));


