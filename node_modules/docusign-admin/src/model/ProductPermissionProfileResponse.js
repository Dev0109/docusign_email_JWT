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
    define(['ApiClient', 'model/PermissionProfileResponse21'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./PermissionProfileResponse21'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.ProductPermissionProfileResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.PermissionProfileResponse21);
  }
}(this, function(ApiClient, PermissionProfileResponse21) {
  'use strict';


  /**
   * The ProductPermissionProfileResponse model module.
   * @module model/ProductPermissionProfileResponse
   */

  /**
   * Constructs a new <code>ProductPermissionProfileResponse</code>.
   * @alias module:model/ProductPermissionProfileResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ProductPermissionProfileResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ProductPermissionProfileResponse} obj Optional instance to populate.
   * @return {module:model/ProductPermissionProfileResponse} The populated <code>ProductPermissionProfileResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('product_id')) {
        obj['product_id'] = ApiClient.convertToType(data['product_id'], 'String');
      }
      if (data.hasOwnProperty('product_name')) {
        obj['product_name'] = ApiClient.convertToType(data['product_name'], 'String');
      }
      if (data.hasOwnProperty('permission_profiles')) {
        obj['permission_profiles'] = ApiClient.convertToType(data['permission_profiles'], [PermissionProfileResponse21]);
      }
      if (data.hasOwnProperty('error_message')) {
        obj['error_message'] = ApiClient.convertToType(data['error_message'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} product_id
   */
  exports.prototype['product_id'] = undefined;
  /**
   * @member {String} product_name
   */
  exports.prototype['product_name'] = undefined;
  /**
   * @member {Array.<module:model/PermissionProfileResponse21>} permission_profiles
   */
  exports.prototype['permission_profiles'] = undefined;
  /**
   * @member {String} error_message
   */
  exports.prototype['error_message'] = undefined;



  return exports;
}));


