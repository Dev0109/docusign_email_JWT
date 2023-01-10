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
    define(['ApiClient', 'model/Permissions'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./Permissions'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RoleForUpdate = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.Permissions);
  }
}(this, function(ApiClient, Permissions) {
  'use strict';


  /**
   * The RoleForUpdate model module.
   * @module model/RoleForUpdate
   */

  /**
   * Constructs a new <code>RoleForUpdate</code>.
   * @alias module:model/RoleForUpdate
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RoleForUpdate</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RoleForUpdate} obj Optional instance to populate.
   * @return {module:model/RoleForUpdate} The populated <code>RoleForUpdate</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('isExternal')) {
        obj['isExternal'] = ApiClient.convertToType(data['isExternal'], 'Boolean');
      }
      if (data.hasOwnProperty('permissions')) {
        obj['permissions'] = Permissions.constructFromObject(data['permissions']);
      }
    }
    return obj;
  }

  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Boolean} isExternal
   */
  exports.prototype['isExternal'] = undefined;
  /**
   * @member {module:model/Permissions} permissions
   */
  exports.prototype['permissions'] = undefined;



  return exports;
}));


