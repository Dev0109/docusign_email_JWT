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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.Document = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The Document model module.
   * @module model/Document
   */

  /**
   * Constructs a new <code>Document</code>.
   * @alias module:model/Document
   * @class
   * @param name {String} 
   * @param base64Contents {String} 
   */
  var exports = function(name, base64Contents) {
    var _this = this;

    _this['name'] = name;    _this['base64Contents'] = base64Contents;
  };

  /**
   * Constructs a <code>Document</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/Document} obj Optional instance to populate.
   * @return {module:model/Document} The populated <code>Document</code> instance.
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
      if (data.hasOwnProperty('roomId')) {
        obj['roomId'] = ApiClient.convertToType(data['roomId'], 'Number');
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
      if (data.hasOwnProperty('contentType')) {
        obj['contentType'] = ApiClient.convertToType(data['contentType'], 'String');
      }
      if (data.hasOwnProperty('base64Contents')) {
        obj['base64Contents'] = ApiClient.convertToType(data['base64Contents'], 'String');
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
   * @member {Number} roomId
   */
  exports.prototype['roomId'] = undefined;
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
   * @member {String} contentType
   */
  exports.prototype['contentType'] = undefined;
  /**
   * @member {String} base64Contents
   */
  exports.prototype['base64Contents'] = undefined;



  return exports;
}));


