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
    define(['ApiClient', 'model/ProductPermissionProfileRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ProductPermissionProfileRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UserProductPermissionProfilesRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.ProductPermissionProfileRequest);
  }
}(this, function(ApiClient, ProductPermissionProfileRequest) {
  'use strict';


  /**
   * The UserProductPermissionProfilesRequest model module.
   * @module model/UserProductPermissionProfilesRequest
   */

  /**
   * Constructs a new <code>UserProductPermissionProfilesRequest</code>.
   * @alias module:model/UserProductPermissionProfilesRequest
   * @class
   * @param email {String} 
   * @param productPermissionProfiles {Array.<module:model/ProductPermissionProfileRequest>} 
   */
  var exports = function(email, productPermissionProfiles) {
    var _this = this;

    _this['email'] = email;    _this['product_permission_profiles'] = productPermissionProfiles;
  };

  /**
   * Constructs a <code>UserProductPermissionProfilesRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserProductPermissionProfilesRequest} obj Optional instance to populate.
   * @return {module:model/UserProductPermissionProfilesRequest} The populated <code>UserProductPermissionProfilesRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('product_permission_profiles')) {
        obj['product_permission_profiles'] = ApiClient.convertToType(data['product_permission_profiles'], [ProductPermissionProfileRequest]);
      }
    }
    return obj;
  }

  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {Array.<module:model/ProductPermissionProfileRequest>} product_permission_profiles
   */
  exports.prototype['product_permission_profiles'] = undefined;



  return exports;
}));


