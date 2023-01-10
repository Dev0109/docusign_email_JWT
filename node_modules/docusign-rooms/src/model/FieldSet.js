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
    define(['ApiClient', 'model/Field'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./Field'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.FieldSet = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.Field);
  }
}(this, function(ApiClient, Field) {
  'use strict';


  /**
   * The FieldSet model module.
   * @module model/FieldSet
   */

  /**
   * Constructs a new <code>FieldSet</code>.
   * @alias module:model/FieldSet
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>FieldSet</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/FieldSet} obj Optional instance to populate.
   * @return {module:model/FieldSet} The populated <code>FieldSet</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('fieldSetId')) {
        obj['fieldSetId'] = ApiClient.convertToType(data['fieldSetId'], 'String');
      }
      if (data.hasOwnProperty('title')) {
        obj['title'] = ApiClient.convertToType(data['title'], 'String');
      }
      if (data.hasOwnProperty('fields')) {
        obj['fields'] = ApiClient.convertToType(data['fields'], [Field]);
      }
    }
    return obj;
  }

  /**
   * @member {String} fieldSetId
   */
  exports.prototype['fieldSetId'] = undefined;
  /**
   * @member {String} title
   */
  exports.prototype['title'] = undefined;
  /**
   * @member {Array.<module:model/Field>} fields
   */
  exports.prototype['fields'] = undefined;



  return exports;
}));


