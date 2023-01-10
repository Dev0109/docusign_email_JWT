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
    define(['ApiClient', 'model/DependsOn', 'model/SelectListFieldOption'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DependsOn'), require('./SelectListFieldOption'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.FieldConfiguration = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.DependsOn, root.DocusignRooms.SelectListFieldOption);
  }
}(this, function(ApiClient, DependsOn, SelectListFieldOption) {
  'use strict';


  /**
   * The FieldConfiguration model module.
   * @module model/FieldConfiguration
   */

  /**
   * Constructs a new <code>FieldConfiguration</code>.
   * @alias module:model/FieldConfiguration
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>FieldConfiguration</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/FieldConfiguration} obj Optional instance to populate.
   * @return {module:model/FieldConfiguration} The populated <code>FieldConfiguration</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('maxValue')) {
        obj['maxValue'] = ApiClient.convertToType(data['maxValue'], 'Number');
      }
      if (data.hasOwnProperty('minValue')) {
        obj['minValue'] = ApiClient.convertToType(data['minValue'], 'Number');
      }
      if (data.hasOwnProperty('multipleOf')) {
        obj['multipleOf'] = ApiClient.convertToType(data['multipleOf'], 'Number');
      }
      if (data.hasOwnProperty('maxLength')) {
        obj['maxLength'] = ApiClient.convertToType(data['maxLength'], 'Number');
      }
      if (data.hasOwnProperty('minLength')) {
        obj['minLength'] = ApiClient.convertToType(data['minLength'], 'Number');
      }
      if (data.hasOwnProperty('pattern')) {
        obj['pattern'] = ApiClient.convertToType(data['pattern'], 'String');
      }
      if (data.hasOwnProperty('isPublisher')) {
        obj['isPublisher'] = ApiClient.convertToType(data['isPublisher'], 'Boolean');
      }
      if (data.hasOwnProperty('dependsOn')) {
        obj['dependsOn'] = ApiClient.convertToType(data['dependsOn'], [DependsOn]);
      }
      if (data.hasOwnProperty('options')) {
        obj['options'] = ApiClient.convertToType(data['options'], [SelectListFieldOption]);
      }
    }
    return obj;
  }

  /**
   * @member {Number} maxValue
   */
  exports.prototype['maxValue'] = undefined;
  /**
   * @member {Number} minValue
   */
  exports.prototype['minValue'] = undefined;
  /**
   * @member {Number} multipleOf
   */
  exports.prototype['multipleOf'] = undefined;
  /**
   * @member {Number} maxLength
   */
  exports.prototype['maxLength'] = undefined;
  /**
   * @member {Number} minLength
   */
  exports.prototype['minLength'] = undefined;
  /**
   * @member {String} pattern
   */
  exports.prototype['pattern'] = undefined;
  /**
   * @member {Boolean} isPublisher
   */
  exports.prototype['isPublisher'] = undefined;
  /**
   * @member {Array.<module:model/DependsOn>} dependsOn
   */
  exports.prototype['dependsOn'] = undefined;
  /**
   * @member {Array.<module:model/SelectListFieldOption>} options
   */
  exports.prototype['options'] = undefined;



  return exports;
}));


