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
    define(['ApiClient', 'model/FieldData'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./FieldData'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.Room = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.FieldData);
  }
}(this, function(ApiClient, FieldData) {
  'use strict';


  /**
   * The Room model module.
   * @module model/Room
   */

  /**
   * Constructs a new <code>Room</code>.
   * @alias module:model/Room
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>Room</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/Room} obj Optional instance to populate.
   * @return {module:model/Room} The populated <code>Room</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('roomId')) {
        obj['roomId'] = ApiClient.convertToType(data['roomId'], 'Number');
      }
      if (data.hasOwnProperty('companyId')) {
        obj['companyId'] = ApiClient.convertToType(data['companyId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('officeId')) {
        obj['officeId'] = ApiClient.convertToType(data['officeId'], 'Number');
      }
      if (data.hasOwnProperty('createdDate')) {
        obj['createdDate'] = ApiClient.convertToType(data['createdDate'], 'Date');
      }
      if (data.hasOwnProperty('submittedForReviewDate')) {
        obj['submittedForReviewDate'] = ApiClient.convertToType(data['submittedForReviewDate'], 'Date');
      }
      if (data.hasOwnProperty('closedDate')) {
        obj['closedDate'] = ApiClient.convertToType(data['closedDate'], 'Date');
      }
      if (data.hasOwnProperty('rejectedDate')) {
        obj['rejectedDate'] = ApiClient.convertToType(data['rejectedDate'], 'Date');
      }
      if (data.hasOwnProperty('createdByUserId')) {
        obj['createdByUserId'] = ApiClient.convertToType(data['createdByUserId'], 'Number');
      }
      if (data.hasOwnProperty('rejectedByUserId')) {
        obj['rejectedByUserId'] = ApiClient.convertToType(data['rejectedByUserId'], 'Number');
      }
      if (data.hasOwnProperty('closedStatusId')) {
        obj['closedStatusId'] = ApiClient.convertToType(data['closedStatusId'], 'String');
      }
      if (data.hasOwnProperty('fieldData')) {
        obj['fieldData'] = FieldData.constructFromObject(data['fieldData']);
      }
    }
    return obj;
  }

  /**
   * @member {Number} roomId
   */
  exports.prototype['roomId'] = undefined;
  /**
   * @member {Number} companyId
   */
  exports.prototype['companyId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} officeId
   */
  exports.prototype['officeId'] = undefined;
  /**
   * @member {Date} createdDate
   */
  exports.prototype['createdDate'] = undefined;
  /**
   * @member {Date} submittedForReviewDate
   */
  exports.prototype['submittedForReviewDate'] = undefined;
  /**
   * @member {Date} closedDate
   */
  exports.prototype['closedDate'] = undefined;
  /**
   * @member {Date} rejectedDate
   */
  exports.prototype['rejectedDate'] = undefined;
  /**
   * @member {Number} createdByUserId
   */
  exports.prototype['createdByUserId'] = undefined;
  /**
   * @member {Number} rejectedByUserId
   */
  exports.prototype['rejectedByUserId'] = undefined;
  /**
   * @member {String} closedStatusId
   */
  exports.prototype['closedStatusId'] = undefined;
  /**
   * @member {module:model/FieldData} fieldData
   */
  exports.prototype['fieldData'] = undefined;



  return exports;
}));


