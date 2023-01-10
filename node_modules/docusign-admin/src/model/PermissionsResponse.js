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
    define(['ApiClient', 'model/PermissionProfileResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./PermissionProfileResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.PermissionsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.PermissionProfileResponse);
  }
}(this, function(ApiClient, PermissionProfileResponse) {
  'use strict';


  /**
   * The PermissionsResponse model module.
   * @module model/PermissionsResponse
   */

  /**
   * Constructs a new <code>PermissionsResponse</code>.
   * @alias module:model/PermissionsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>PermissionsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/PermissionsResponse} obj Optional instance to populate.
   * @return {module:model/PermissionsResponse} The populated <code>PermissionsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('permissions')) {
        obj['permissions'] = ApiClient.convertToType(data['permissions'], [PermissionProfileResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/PermissionProfileResponse>} permissions
   */
  exports.prototype['permissions'] = undefined;



  return exports;
}));


