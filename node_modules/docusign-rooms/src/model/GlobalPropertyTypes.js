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
    define(['ApiClient', 'model/PropertyType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./PropertyType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalPropertyTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.PropertyType);
  }
}(this, function(ApiClient, PropertyType) {
  'use strict';


  /**
   * The GlobalPropertyTypes model module.
   * @module model/GlobalPropertyTypes
   */

  /**
   * Constructs a new <code>GlobalPropertyTypes</code>.
   * @alias module:model/GlobalPropertyTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalPropertyTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalPropertyTypes} obj Optional instance to populate.
   * @return {module:model/GlobalPropertyTypes} The populated <code>GlobalPropertyTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('propertyTypes')) {
        obj['propertyTypes'] = ApiClient.convertToType(data['propertyTypes'], [PropertyType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/PropertyType>} propertyTypes
   */
  exports.prototype['propertyTypes'] = undefined;



  return exports;
}));


