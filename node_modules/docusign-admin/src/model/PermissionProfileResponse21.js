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
    root.DocusignAdmin.PermissionProfileResponse21 = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The PermissionProfileResponse21 model module.
   * @module model/PermissionProfileResponse21
   */

  /**
   * Constructs a new <code>PermissionProfileResponse21</code>.
   * @alias module:model/PermissionProfileResponse21
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>PermissionProfileResponse21</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/PermissionProfileResponse21} obj Optional instance to populate.
   * @return {module:model/PermissionProfileResponse21} The populated <code>PermissionProfileResponse21</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('permission_profile_id')) {
        obj['permission_profile_id'] = ApiClient.convertToType(data['permission_profile_id'], 'String');
      }
      if (data.hasOwnProperty('permission_profile_name')) {
        obj['permission_profile_name'] = ApiClient.convertToType(data['permission_profile_name'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} permission_profile_id
   */
  exports.prototype['permission_profile_id'] = undefined;
  /**
   * @member {String} permission_profile_name
   */
  exports.prototype['permission_profile_name'] = undefined;



  return exports;
}));


