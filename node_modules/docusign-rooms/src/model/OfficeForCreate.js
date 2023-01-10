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
    root.DocusignRooms.OfficeForCreate = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OfficeForCreate model module.
   * @module model/OfficeForCreate
   */

  /**
   * Constructs a new <code>OfficeForCreate</code>.
   * @alias module:model/OfficeForCreate
   * @class
   * @param name {String} 
   */
  var exports = function(name) {
    var _this = this;

    _this['name'] = name;
  };

  /**
   * Constructs a <code>OfficeForCreate</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OfficeForCreate} obj Optional instance to populate.
   * @return {module:model/OfficeForCreate} The populated <code>OfficeForCreate</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('regionId')) {
        obj['regionId'] = ApiClient.convertToType(data['regionId'], 'Number');
      }
      if (data.hasOwnProperty('address1')) {
        obj['address1'] = ApiClient.convertToType(data['address1'], 'String');
      }
      if (data.hasOwnProperty('address2')) {
        obj['address2'] = ApiClient.convertToType(data['address2'], 'String');
      }
      if (data.hasOwnProperty('city')) {
        obj['city'] = ApiClient.convertToType(data['city'], 'String');
      }
      if (data.hasOwnProperty('stateId')) {
        obj['stateId'] = ApiClient.convertToType(data['stateId'], 'String');
      }
      if (data.hasOwnProperty('postalCode')) {
        obj['postalCode'] = ApiClient.convertToType(data['postalCode'], 'String');
      }
      if (data.hasOwnProperty('countryId')) {
        obj['countryId'] = ApiClient.convertToType(data['countryId'], 'String');
      }
      if (data.hasOwnProperty('timeZoneId')) {
        obj['timeZoneId'] = ApiClient.convertToType(data['timeZoneId'], 'String');
      }
      if (data.hasOwnProperty('phone')) {
        obj['phone'] = ApiClient.convertToType(data['phone'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} regionId
   */
  exports.prototype['regionId'] = undefined;
  /**
   * @member {String} address1
   */
  exports.prototype['address1'] = undefined;
  /**
   * @member {String} address2
   */
  exports.prototype['address2'] = undefined;
  /**
   * @member {String} city
   */
  exports.prototype['city'] = undefined;
  /**
   * @member {String} stateId
   */
  exports.prototype['stateId'] = undefined;
  /**
   * @member {String} postalCode
   */
  exports.prototype['postalCode'] = undefined;
  /**
   * @member {String} countryId
   */
  exports.prototype['countryId'] = undefined;
  /**
   * @member {String} timeZoneId
   */
  exports.prototype['timeZoneId'] = undefined;
  /**
   * @member {String} phone
   */
  exports.prototype['phone'] = undefined;



  return exports;
}));


