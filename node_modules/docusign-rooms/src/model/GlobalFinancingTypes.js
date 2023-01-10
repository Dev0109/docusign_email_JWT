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
    define(['ApiClient', 'model/FinancingType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./FinancingType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalFinancingTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.FinancingType);
  }
}(this, function(ApiClient, FinancingType) {
  'use strict';


  /**
   * The GlobalFinancingTypes model module.
   * @module model/GlobalFinancingTypes
   */

  /**
   * Constructs a new <code>GlobalFinancingTypes</code>.
   * @alias module:model/GlobalFinancingTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalFinancingTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalFinancingTypes} obj Optional instance to populate.
   * @return {module:model/GlobalFinancingTypes} The populated <code>GlobalFinancingTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('financingTypes')) {
        obj['financingTypes'] = ApiClient.convertToType(data['financingTypes'], [FinancingType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/FinancingType>} financingTypes
   */
  exports.prototype['financingTypes'] = undefined;



  return exports;
}));


