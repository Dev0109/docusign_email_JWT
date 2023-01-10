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
    define(['ApiClient', 'model/OrganizationExportResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationExportResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationExportsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationExportResponse);
  }
}(this, function(ApiClient, OrganizationExportResponse) {
  'use strict';


  /**
   * The OrganizationExportsResponse model module.
   * @module model/OrganizationExportsResponse
   */

  /**
   * Constructs a new <code>OrganizationExportsResponse</code>.
   * @alias module:model/OrganizationExportsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationExportsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationExportsResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationExportsResponse} The populated <code>OrganizationExportsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('exports')) {
        obj['exports'] = ApiClient.convertToType(data['exports'], [OrganizationExportResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OrganizationExportResponse>} exports
   */
  exports.prototype['exports'] = undefined;



  return exports;
}));


