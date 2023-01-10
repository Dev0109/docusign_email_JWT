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
    root.DocusignAdmin.OrganizationImportResponseErrorRollup = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrganizationImportResponseErrorRollup model module.
   * @module model/OrganizationImportResponseErrorRollup
   */

  /**
   * Constructs a new <code>OrganizationImportResponseErrorRollup</code>.
   * @alias module:model/OrganizationImportResponseErrorRollup
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationImportResponseErrorRollup</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationImportResponseErrorRollup} obj Optional instance to populate.
   * @return {module:model/OrganizationImportResponseErrorRollup} The populated <code>OrganizationImportResponseErrorRollup</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('error_type')) {
        obj['error_type'] = ApiClient.convertToType(data['error_type'], 'String');
      }
      if (data.hasOwnProperty('count')) {
        obj['count'] = ApiClient.convertToType(data['count'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {String} error_type
   */
  exports.prototype['error_type'] = undefined;
  /**
   * @member {Number} count
   */
  exports.prototype['count'] = undefined;



  return exports;
}));


