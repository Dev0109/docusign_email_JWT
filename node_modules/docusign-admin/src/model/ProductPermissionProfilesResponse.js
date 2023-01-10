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
    define(['ApiClient', 'model/ProductPermissionProfileResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ProductPermissionProfileResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.ProductPermissionProfilesResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.ProductPermissionProfileResponse);
  }
}(this, function(ApiClient, ProductPermissionProfileResponse) {
  'use strict';


  /**
   * The ProductPermissionProfilesResponse model module.
   * @module model/ProductPermissionProfilesResponse
   */

  /**
   * Constructs a new <code>ProductPermissionProfilesResponse</code>.
   * @alias module:model/ProductPermissionProfilesResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ProductPermissionProfilesResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ProductPermissionProfilesResponse} obj Optional instance to populate.
   * @return {module:model/ProductPermissionProfilesResponse} The populated <code>ProductPermissionProfilesResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('product_permission_profiles')) {
        obj['product_permission_profiles'] = ApiClient.convertToType(data['product_permission_profiles'], [ProductPermissionProfileResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/ProductPermissionProfileResponse>} product_permission_profiles
   */
  exports.prototype['product_permission_profiles'] = undefined;



  return exports;
}));


