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
    define(['ApiClient', 'model/CustomData', 'model/Field', 'model/FieldConfiguration'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./CustomData'), require('./Field'), require('./FieldConfiguration'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.Field = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.CustomData, root.DocusignRooms.Field, root.DocusignRooms.FieldConfiguration);
  }
}(this, function(ApiClient, CustomData, Field, FieldConfiguration) {
  'use strict';


  /**
   * The Field model module.
   * @module model/Field
   */

  /**
   * Constructs a new <code>Field</code>.
   * @alias module:model/Field
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>Field</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/Field} obj Optional instance to populate.
   * @return {module:model/Field} The populated <code>Field</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('fieldId')) {
        obj['fieldId'] = ApiClient.convertToType(data['fieldId'], 'String');
      }
      if (data.hasOwnProperty('fieldDefinitionId')) {
        obj['fieldDefinitionId'] = ApiClient.convertToType(data['fieldDefinitionId'], 'String');
      }
      if (data.hasOwnProperty('title')) {
        obj['title'] = ApiClient.convertToType(data['title'], 'String');
      }
      if (data.hasOwnProperty('apiName')) {
        obj['apiName'] = ApiClient.convertToType(data['apiName'], 'String');
      }
      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('fields')) {
        obj['fields'] = ApiClient.convertToType(data['fields'], [Field]);
      }
      if (data.hasOwnProperty('configuration')) {
        obj['configuration'] = FieldConfiguration.constructFromObject(data['configuration']);
      }
      if (data.hasOwnProperty('customData')) {
        obj['customData'] = CustomData.constructFromObject(data['customData']);
      }
    }
    return obj;
  }

  /**
   * @member {String} fieldId
   */
  exports.prototype['fieldId'] = undefined;
  /**
   * @member {String} fieldDefinitionId
   */
  exports.prototype['fieldDefinitionId'] = undefined;
  /**
   * @member {String} title
   */
  exports.prototype['title'] = undefined;
  /**
   * @member {String} apiName
   */
  exports.prototype['apiName'] = undefined;
  /**
   * @member {String} type
   */
  exports.prototype['type'] = undefined;
  /**
   * @member {Array.<module:model/Field>} fields
   */
  exports.prototype['fields'] = undefined;
  /**
   * @member {module:model/FieldConfiguration} configuration
   */
  exports.prototype['configuration'] = undefined;
  /**
   * @member {module:model/CustomData} customData
   */
  exports.prototype['customData'] = undefined;



  return exports;
}));


