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
    define(['ApiClient', 'model/RoomDocumentOwner'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./RoomDocumentOwner'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RoomDocument = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.RoomDocumentOwner);
  }
}(this, function(ApiClient, RoomDocumentOwner) {
  'use strict';


  /**
   * The RoomDocument model module.
   * @module model/RoomDocument
   */

  /**
   * Constructs a new <code>RoomDocument</code>.
   * @alias module:model/RoomDocument
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RoomDocument</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RoomDocument} obj Optional instance to populate.
   * @return {module:model/RoomDocument} The populated <code>RoomDocument</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('documentId')) {
        obj['documentId'] = ApiClient.convertToType(data['documentId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('ownerId')) {
        obj['ownerId'] = ApiClient.convertToType(data['ownerId'], 'Number');
      }
      if (data.hasOwnProperty('size')) {
        obj['size'] = ApiClient.convertToType(data['size'], 'Number');
      }
      if (data.hasOwnProperty('folderId')) {
        obj['folderId'] = ApiClient.convertToType(data['folderId'], 'Number');
      }
      if (data.hasOwnProperty('createdDate')) {
        obj['createdDate'] = ApiClient.convertToType(data['createdDate'], 'Date');
      }
      if (data.hasOwnProperty('isSigned')) {
        obj['isSigned'] = ApiClient.convertToType(data['isSigned'], 'Boolean');
      }
      if (data.hasOwnProperty('docuSignFormId')) {
        obj['docuSignFormId'] = ApiClient.convertToType(data['docuSignFormId'], 'String');
      }
      if (data.hasOwnProperty('isArchived')) {
        obj['isArchived'] = ApiClient.convertToType(data['isArchived'], 'Boolean');
      }
      if (data.hasOwnProperty('isVirtual')) {
        obj['isVirtual'] = ApiClient.convertToType(data['isVirtual'], 'Boolean');
      }
      if (data.hasOwnProperty('owner')) {
        obj['owner'] = RoomDocumentOwner.constructFromObject(data['owner']);
      }
    }
    return obj;
  }

  /**
   * @member {Number} documentId
   */
  exports.prototype['documentId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} ownerId
   */
  exports.prototype['ownerId'] = undefined;
  /**
   * @member {Number} size
   */
  exports.prototype['size'] = undefined;
  /**
   * @member {Number} folderId
   */
  exports.prototype['folderId'] = undefined;
  /**
   * @member {Date} createdDate
   */
  exports.prototype['createdDate'] = undefined;
  /**
   * @member {Boolean} isSigned
   */
  exports.prototype['isSigned'] = undefined;
  /**
   * @member {String} docuSignFormId
   */
  exports.prototype['docuSignFormId'] = undefined;
  /**
   * @member {Boolean} isArchived
   */
  exports.prototype['isArchived'] = undefined;
  /**
   * @member {Boolean} isVirtual
   */
  exports.prototype['isVirtual'] = undefined;
  /**
   * @member {module:model/RoomDocumentOwner} owner
   */
  exports.prototype['owner'] = undefined;



  return exports;
}));


