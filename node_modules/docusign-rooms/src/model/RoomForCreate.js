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
    define(['ApiClient', 'model/FieldDataForCreate'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./FieldDataForCreate'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RoomForCreate = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.FieldDataForCreate);
  }
}(this, function(ApiClient, FieldDataForCreate) {
  'use strict';


  /**
   * The RoomForCreate model module.
   * @module model/RoomForCreate
   */

  /**
   * Constructs a new <code>RoomForCreate</code>.
   * @alias module:model/RoomForCreate
   * @class
   * @param name {String} 
   * @param roleId {Number} 
   */
  var exports = function(name, roleId) {
    var _this = this;

    _this['name'] = name;    _this['roleId'] = roleId;
  };

  /**
   * Constructs a <code>RoomForCreate</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RoomForCreate} obj Optional instance to populate.
   * @return {module:model/RoomForCreate} The populated <code>RoomForCreate</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('roleId')) {
        obj['roleId'] = ApiClient.convertToType(data['roleId'], 'Number');
      }
      if (data.hasOwnProperty('transactionSideId')) {
        obj['transactionSideId'] = ApiClient.convertToType(data['transactionSideId'], 'String');
      }
      if (data.hasOwnProperty('ownerId')) {
        obj['ownerId'] = ApiClient.convertToType(data['ownerId'], 'Number');
      }
      if (data.hasOwnProperty('templateId')) {
        obj['templateId'] = ApiClient.convertToType(data['templateId'], 'Number');
      }
      if (data.hasOwnProperty('officeId')) {
        obj['officeId'] = ApiClient.convertToType(data['officeId'], 'Number');
      }
      if (data.hasOwnProperty('fieldData')) {
        obj['fieldData'] = FieldDataForCreate.constructFromObject(data['fieldData']);
      }
    }
    return obj;
  }

  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} roleId
   */
  exports.prototype['roleId'] = undefined;
  /**
   * Required for a real estate company; otherwise ignored.
   * @member {String} transactionSideId
   */
  exports.prototype['transactionSideId'] = undefined;
  /**
   * @member {Number} ownerId
   */
  exports.prototype['ownerId'] = undefined;
  /**
   * @member {Number} templateId
   */
  exports.prototype['templateId'] = undefined;
  /**
   * @member {Number} officeId
   */
  exports.prototype['officeId'] = undefined;
  /**
   * @member {module:model/FieldDataForCreate} fieldData
   */
  exports.prototype['fieldData'] = undefined;



  return exports;
}));


