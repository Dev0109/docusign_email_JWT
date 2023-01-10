/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/ESignPermissionProfile'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ESignPermissionProfile'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.ESignPermissionProfileList = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.ESignPermissionProfile);
  }
}(this, function(ApiClient, ESignPermissionProfile) {
  'use strict';


  /**
   * The ESignPermissionProfileList model module.
   * @module model/ESignPermissionProfileList
   */

  /**
   * Constructs a new <code>ESignPermissionProfileList</code>.
   * @alias module:model/ESignPermissionProfileList
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ESignPermissionProfileList</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ESignPermissionProfileList} obj Optional instance to populate.
   * @return {module:model/ESignPermissionProfileList} The populated <code>ESignPermissionProfileList</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('permissionProfiles')) {
        obj['permissionProfiles'] = ApiClient.convertToType(data['permissionProfiles'], [ESignPermissionProfile]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/ESignPermissionProfile>} permissionProfiles
   */
  exports.prototype['permissionProfiles'] = undefined;



  return exports;
}));


