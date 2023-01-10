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
    root.DocusignAdmin.OrganizationImportResponseWarningRollup = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrganizationImportResponseWarningRollup model module.
   * @module model/OrganizationImportResponseWarningRollup
   */

  /**
   * Constructs a new <code>OrganizationImportResponseWarningRollup</code>.
   * @alias module:model/OrganizationImportResponseWarningRollup
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationImportResponseWarningRollup</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationImportResponseWarningRollup} obj Optional instance to populate.
   * @return {module:model/OrganizationImportResponseWarningRollup} The populated <code>OrganizationImportResponseWarningRollup</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('warning_type')) {
        obj['warning_type'] = ApiClient.convertToType(data['warning_type'], 'String');
      }
      if (data.hasOwnProperty('count')) {
        obj['count'] = ApiClient.convertToType(data['count'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {String} warning_type
   */
  exports.prototype['warning_type'] = undefined;
  /**
   * @member {Number} count
   */
  exports.prototype['count'] = undefined;



  return exports;
}));


