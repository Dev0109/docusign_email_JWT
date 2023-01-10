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
    define(['ApiClient', 'model/ESignAccountRoleSettings'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ESignAccountRoleSettings'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.ESignPermissionProfile = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.ESignAccountRoleSettings);
  }
}(this, function(ApiClient, ESignAccountRoleSettings) {
  'use strict';


  /**
   * The ESignPermissionProfile model module.
   * @module model/ESignPermissionProfile
   */

  /**
   * Constructs a new <code>ESignPermissionProfile</code>.
   * @alias module:model/ESignPermissionProfile
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ESignPermissionProfile</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ESignPermissionProfile} obj Optional instance to populate.
   * @return {module:model/ESignPermissionProfile} The populated <code>ESignPermissionProfile</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('eSignPermissionProfileId')) {
        obj['eSignPermissionProfileId'] = ApiClient.convertToType(data['eSignPermissionProfileId'], 'String');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('settings')) {
        obj['settings'] = ESignAccountRoleSettings.constructFromObject(data['settings']);
      }
    }
    return obj;
  }

  /**
   * @member {String} eSignPermissionProfileId
   */
  exports.prototype['eSignPermissionProfileId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {module:model/ESignAccountRoleSettings} settings
   */
  exports.prototype['settings'] = undefined;



  return exports;
}));


