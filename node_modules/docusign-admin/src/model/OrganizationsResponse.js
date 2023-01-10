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
    define(['ApiClient', 'model/OrganizationResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationResponse);
  }
}(this, function(ApiClient, OrganizationResponse) {
  'use strict';


  /**
   * The OrganizationsResponse model module.
   * @module model/OrganizationsResponse
   */

  /**
   * Constructs a new <code>OrganizationsResponse</code>.
   * @alias module:model/OrganizationsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationsResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationsResponse} The populated <code>OrganizationsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('organizations')) {
        obj['organizations'] = ApiClient.convertToType(data['organizations'], [OrganizationResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OrganizationResponse>} organizations
   */
  exports.prototype['organizations'] = undefined;



  return exports;
}));


