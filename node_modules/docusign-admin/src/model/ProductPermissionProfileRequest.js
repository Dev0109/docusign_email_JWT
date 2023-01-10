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
    root.DocusignAdmin.ProductPermissionProfileRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ProductPermissionProfileRequest model module.
   * @module model/ProductPermissionProfileRequest
   */

  /**
   * Constructs a new <code>ProductPermissionProfileRequest</code>.
   * @alias module:model/ProductPermissionProfileRequest
   * @class
   * @param productId {String} 
   * @param permissionProfileId {String} 
   */
  var exports = function(productId, permissionProfileId) {
    var _this = this;

    _this['product_id'] = productId;    _this['permission_profile_id'] = permissionProfileId;
  };

  /**
   * Constructs a <code>ProductPermissionProfileRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ProductPermissionProfileRequest} obj Optional instance to populate.
   * @return {module:model/ProductPermissionProfileRequest} The populated <code>ProductPermissionProfileRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('product_id')) {
        obj['product_id'] = ApiClient.convertToType(data['product_id'], 'String');
      }
      if (data.hasOwnProperty('permission_profile_id')) {
        obj['permission_profile_id'] = ApiClient.convertToType(data['permission_profile_id'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} product_id
   */
  exports.prototype['product_id'] = undefined;
  /**
   * @member {String} permission_profile_id
   */
  exports.prototype['permission_profile_id'] = undefined;



  return exports;
}));


