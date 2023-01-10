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
    define(['ApiClient', 'model/OrgReportListResponseOrgReport'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrgReportListResponseOrgReport'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrgReportListResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrgReportListResponseOrgReport);
  }
}(this, function(ApiClient, OrgReportListResponseOrgReport) {
  'use strict';


  /**
   * The OrgReportListResponse model module.
   * @module model/OrgReportListResponse
   */

  /**
   * Constructs a new <code>OrgReportListResponse</code>.
   * @alias module:model/OrgReportListResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrgReportListResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrgReportListResponse} obj Optional instance to populate.
   * @return {module:model/OrgReportListResponse} The populated <code>OrgReportListResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('reports')) {
        obj['reports'] = ApiClient.convertToType(data['reports'], [OrgReportListResponseOrgReport]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OrgReportListResponseOrgReport>} reports
   */
  exports.prototype['reports'] = undefined;



  return exports;
}));


