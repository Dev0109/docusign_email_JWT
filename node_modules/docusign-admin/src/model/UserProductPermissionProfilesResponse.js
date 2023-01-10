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
    root.DocusignAdmin.UserProductPermissionProfilesResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.ProductPermissionProfileResponse);
  }
}(this, function(ApiClient, ProductPermissionProfileResponse) {
  'use strict';


  /**
   * The UserProductPermissionProfilesResponse model module.
   * @module model/UserProductPermissionProfilesResponse
   */

  /**
   * Constructs a new <code>UserProductPermissionProfilesResponse</code>.
   * @alias module:model/UserProductPermissionProfilesResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UserProductPermissionProfilesResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserProductPermissionProfilesResponse} obj Optional instance to populate.
   * @return {module:model/UserProductPermissionProfilesResponse} The populated <code>UserProductPermissionProfilesResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('user_id')) {
        obj['user_id'] = ApiClient.convertToType(data['user_id'], 'String');
      }
      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('product_permission_profiles')) {
        obj['product_permission_profiles'] = ApiClient.convertToType(data['product_permission_profiles'], [ProductPermissionProfileResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {String} user_id
   */
  exports.prototype['user_id'] = undefined;
  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {Array.<module:model/ProductPermissionProfileResponse>} product_permission_profiles
   */
  exports.prototype['product_permission_profiles'] = undefined;



  return exports;
}));


