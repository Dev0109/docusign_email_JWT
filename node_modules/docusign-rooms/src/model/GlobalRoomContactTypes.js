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
    define(['ApiClient', 'model/RoomContactType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./RoomContactType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalRoomContactTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.RoomContactType);
  }
}(this, function(ApiClient, RoomContactType) {
  'use strict';


  /**
   * The GlobalRoomContactTypes model module.
   * @module model/GlobalRoomContactTypes
   */

  /**
   * Constructs a new <code>GlobalRoomContactTypes</code>.
   * @alias module:model/GlobalRoomContactTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalRoomContactTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalRoomContactTypes} obj Optional instance to populate.
   * @return {module:model/GlobalRoomContactTypes} The populated <code>GlobalRoomContactTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('roomContactTypes')) {
        obj['roomContactTypes'] = ApiClient.convertToType(data['roomContactTypes'], [RoomContactType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/RoomContactType>} roomContactTypes
   */
  exports.prototype['roomContactTypes'] = undefined;



  return exports;
}));


