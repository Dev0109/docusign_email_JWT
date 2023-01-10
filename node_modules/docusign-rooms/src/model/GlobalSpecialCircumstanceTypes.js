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
    define(['ApiClient', 'model/SpecialCircumstanceType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./SpecialCircumstanceType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalSpecialCircumstanceTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.SpecialCircumstanceType);
  }
}(this, function(ApiClient, SpecialCircumstanceType) {
  'use strict';


  /**
   * The GlobalSpecialCircumstanceTypes model module.
   * @module model/GlobalSpecialCircumstanceTypes
   */

  /**
   * Constructs a new <code>GlobalSpecialCircumstanceTypes</code>.
   * @alias module:model/GlobalSpecialCircumstanceTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalSpecialCircumstanceTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalSpecialCircumstanceTypes} obj Optional instance to populate.
   * @return {module:model/GlobalSpecialCircumstanceTypes} The populated <code>GlobalSpecialCircumstanceTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('specialCircumstanceTypes')) {
        obj['specialCircumstanceTypes'] = ApiClient.convertToType(data['specialCircumstanceTypes'], [SpecialCircumstanceType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/SpecialCircumstanceType>} specialCircumstanceTypes
   */
  exports.prototype['specialCircumstanceTypes'] = undefined;



  return exports;
}));


