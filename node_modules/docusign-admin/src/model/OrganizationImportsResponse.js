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
    define(['ApiClient', 'model/OrganizationImportResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationImportResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationImportsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationImportResponse);
  }
}(this, function(ApiClient, OrganizationImportResponse) {
  'use strict';


  /**
   * The OrganizationImportsResponse model module.
   * @module model/OrganizationImportsResponse
   */

  /**
   * Constructs a new <code>OrganizationImportsResponse</code>.
   * @alias module:model/OrganizationImportsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationImportsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationImportsResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationImportsResponse} The populated <code>OrganizationImportsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('imports')) {
        obj['imports'] = ApiClient.convertToType(data['imports'], [OrganizationImportResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OrganizationImportResponse>} imports
   */
  exports.prototype['imports'] = undefined;



  return exports;
}));


